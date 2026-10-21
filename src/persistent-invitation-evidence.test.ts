import { describe, expect, it, vi } from 'vitest'
import { finalizeEvent, generateSecretKey, verifiedSymbol, type Event } from 'nostr-tools/pure'
import { createRoomInvitation, deriveInvitationId, encodeInvitationRetirement } from './invitation.js'
import { encodePersistentInvitation, requestPersistentRoomAdmission } from './persistent-invitation.js'
import { requestPersistentRoomAdmissionEvidence as query, revalidatePersistentInvitationEvidence as validate, revalidatePersistentInvitationSource as revalidateSource,
  PersistentInvitationEvidenceQueryError, MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS, MAX_PERSISTENT_INVITATION_EVIDENCE_DELIVERIES,
  MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS, MAX_PERSISTENT_INVITATION_EVIDENCE_BYTES } from './persistent-invitation-evidence.js'
import type { RelayTransport } from './transport.js'
import * as verifier from './verify.js'
import { nip44 } from 'nostr-tools'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { PERSISTENT_INVITATION_LABELS } from './persistent-invitation.js'
import * as roomModule from './room.js'

const now = 1_800_000_000
function fixture() {
  const host = createRoomInvitation(true), secret = new Uint8Array(32).fill(42)
  const invite = (extra: Partial<Parameters<typeof encodePersistentInvitation>[0]> = {}) => encodePersistentInvitation({ ...host, roomSecret: secret, now, ...extra })
  return { host, secret, invite }
}
function replay(events: Event[], eose = true) {
  const stop = vi.fn(), publish = vi.fn(async () => {}), close = vi.fn()
  const transport: RelayTransport = { publish, close, subscribe: (_filters, onEvent, onEose) => {
    for (const event of events) onEvent(event)
    if (eose) onEose?.()
    return stop
  } }
  return { transport, stop, publish, close }
}

describe('bounded persistent invitation evidence', () => {
  it.each(['extra', 'duplicate', 'bad-version', 'wrong-room', 'short-secret', 'bad-end', 'false-destruct', 'bad-relays', 'bad-storage', 'duplicate-storage-host', 'extra-tag', 'missing-expiration'])('independently refuses malformed signed group evidence: %s', async fault => {
    const f = fixture(), event = f.invite({ endsAt: now + 100 })
    const key = hkdf(sha256, f.host.invitation.bearer, undefined, PERSISTENT_INVITATION_LABELS[0], 32)
    try {
      const body = JSON.parse(nip44.v2.decrypt(event.content, key))
      if (fault === 'extra') body.extra = true
      if (fault === 'bad-version') body.v = 4
      if (fault === 'wrong-room') body.room = '0'.repeat(64)
      if (fault === 'short-secret') body.secret = 'AA'
      if (fault === 'bad-end') body.ends = 'tomorrow'
      if (fault === 'false-destruct') body.destruct = false
      if (fault === 'bad-relays') body.relays = ['http://unsafe.example/']
      if (fault === 'bad-storage') body.storage = ['http://unsafe.example']
      if (fault === 'duplicate-storage-host') body.storage = ['https://node.example.net', 'https://node.example.net:8443']
      const plaintext = fault === 'duplicate' ? JSON.stringify(body).replace('"v":3', '"v":3,"v":3') : JSON.stringify(body)
      const tags = fault === 'extra-tag' ? [...event.tags, ['extra', 'tag']] : fault === 'missing-expiration' ? [event.tags[0]!] : event.tags
      const bad = finalizeEvent({ ...event, tags, content: nip44.v2.encrypt(plaintext, key) }, f.host.inviterSk)
      const result = await query({ transport: replay([bad]).transport, invitation: f.host.invitation })
      expect(result.outcome).toMatchObject({ status: 'held', reason: 'unavailable' })
      expect(result.evidence.events).toEqual([])
    } finally { key.fill(0) }
  })
  it('retains immutable canonical carriers and exact invitation/event identities with no publication', async () => {
    const f = fixture(), event = f.invite({ relays: ['wss://fixed.example/'] }), r = replay([event])
    const result = await query({ transport: r.transport, invitation: f.host.invitation })
    expect(result.evidence.invitationId).toBe(deriveInvitationId(f.host.invitation))
    expect(result.evidence.eventIds).toEqual([event.id])
    expect(result.evidence.events).toEqual([JSON.stringify({ id: event.id, pubkey: event.pubkey, created_at: event.created_at, kind: event.kind, tags: event.tags, content: event.content, sig: event.sig })])
    expect(result.outcome.status).toBe('admitted')
    if (result.outcome.status !== 'admitted') throw new Error('held')
    expect(result.outcome.admission).toEqual({ secret: f.secret, persistent: true, epoch: 0, relays: ['wss://fixed.example/'] })
    expect(result.outcome.contributors).toEqual({ room: [event.id], ends: [], destruct: [], relays: [event.id] })
    expect(Object.isFrozen(result.evidence)).toBe(true)
    expect(Object.isFrozen(result.evidence.events)).toBe(true)
    expect(r.stop).toHaveBeenCalledTimes(1)
    expect(r.publish).not.toHaveBeenCalled()
    expect(r.close).not.toHaveBeenCalled()
    event.tags[0]![1] = 'changed'
    result.outcome.admission.secret.fill(0)
    const read = validate({ evidence: result.evidence, invitation: f.host.invitation, expectedRoomSecret: f.secret })
    expect(read.outcome.status).toBe('admitted')
    if (read.outcome.status === 'admitted') expect(read.outcome.admission.secret).toEqual(f.secret)
  })

  it('reproduces earliest end, sticky destruction and newest relay contributors in either arrival order', async () => {
    const f = fixture(), old = f.invite({ endsAt: now + 100, destruct: true, relays: ['wss://old.example/'] }), latest = f.invite({ now: now + 1, endsAt: now + 200, relays: ['wss://new.example/'] }), legacy = f.invite({ now: now + 2 })
    let saved
    for (const events of [[old, latest, legacy], [legacy, latest, old]]) {
      const result = await query({ transport: replay(events).transport, invitation: f.host.invitation })
      expect(result.outcome.status).toBe('admitted')
      if (result.outcome.status !== 'admitted') throw new Error('held')
      expect(result.outcome.admission).toEqual({ secret: f.secret, persistent: true, epoch: 0, endsAt: now + 100, destruct: true, relays: ['wss://new.example/'] })
      expect(result.outcome.contributors.ends).toEqual([old.id])
      expect(result.outcome.contributors.destruct).toEqual([old.id])
      expect(result.outcome.contributors.relays).toEqual([latest.id])
      if (saved) expect(result.evidence).toEqual(saved)
      saved = result.evidence
    }
  })

  it('holds equal-time newest differing lists deterministically; legacy request still keeps first', async () => {
    const f = fixture(), a = f.invite({ relays: ['wss://a.example/'] }), b = f.invite({ relays: ['wss://b.example/'] })
    for (const events of [[a, b], [b, a]]) {
      const result = await query({ transport: replay(events).transport, invitation: f.host.invitation })
      expect(result.outcome).toEqual({ status: 'held', reason: 'conflicting-relays', retirementEventIds: [] })
      expect(result.evidence.events).toHaveLength(2)
      const legacy = await requestPersistentRoomAdmission({ transport: replay(events).transport, invitation: f.host.invitation })
      expect(legacy.relays).toEqual(events[0] === a ? ['wss://a.example/'] : ['wss://b.example/'])
    }
  })

  describe('storage nodes', () => {
    it('leave contributors exactly as 0.13.0 wrote them when no copy names storage', async () => {
      // A proof stored under 0.13.0 holds `contributors` as JSON and is compared
      // with what a re-query selects, key for key, so no `storage` key may appear.
      const f = fixture(), old = f.invite({ endsAt: now + 100, destruct: true, relays: ['wss://old.example/'] }), latest = f.invite({ now: now + 1, relays: ['wss://new.example/'] })
      const result = await query({ transport: replay([old, latest]).transport, invitation: f.host.invitation })
      if (result.outcome.status !== 'admitted') throw new Error('held')
      const shape013 = { room: [old.id, latest.id].sort(), ends: [old.id], destruct: [old.id], relays: [latest.id] }
      expect(result.outcome.contributors).toEqual(shape013)
      expect(JSON.stringify(result.outcome.contributors)).toBe(JSON.stringify(shape013))
      expect(Object.keys(result.outcome.contributors)).toEqual(['room', 'ends', 'destruct', 'relays'])
      expect(result.outcome.admission).not.toHaveProperty('storage')
      expect(result.outcome.admission).not.toHaveProperty('storageAt')
      // The same through a revalidation of the retained evidence.
      const again = validate({ evidence: result.evidence, invitation: f.host.invitation })
      expect(JSON.stringify(again.outcome)).toBe(JSON.stringify(result.outcome))
    })

    const A = ['https://a.example.net'], B = ['https://b.example.net', 'https://c.example.org:8443/wb']

    it('are accepted by the strict path, with their version and contributor', async () => {
      const f = fixture(), event = f.invite({ relays: ['wss://fixed.example/'], storage: B })
      const result = await query({ transport: replay([event]).transport, invitation: f.host.invitation })
      expect(result.outcome.status).toBe('admitted')
      if (result.outcome.status !== 'admitted') throw new Error('held')
      expect(result.outcome.admission).toEqual({ secret: f.secret, persistent: true, epoch: 0, relays: ['wss://fixed.example/'], storage: B, storageAt: now })
      expect(result.outcome.contributors).toEqual({ room: [event.id], ends: [], destruct: [], relays: [event.id], storage: [event.id] })
      expect(validate({ evidence: result.evidence, invitation: f.host.invitation }).outcome).toEqual(result.outcome)
      // An empty list is a list: the authority withdrew every node.
      const withdrawn = await query({ transport: replay([f.invite({ storage: [] })]).transport, invitation: f.host.invitation })
      expect(withdrawn.outcome).toMatchObject({ status: 'admitted', admission: { storage: [], storageAt: now } })
    })

    it('are carried through a retained single source with their version', () => {
      const f = fixture(), event = f.invite({ endsAt: now + 100, storage: A })
      const source = revalidateSource({ event, invitation: f.host.invitation, expectedRoomSecret: f.secret })
      expect(source.admission).toMatchObject({ endsAt: now + 100, storage: A, storageAt: now })
      expect(revalidateSource({ event: source.event, invitation: f.host.invitation, expectedRoomSecret: f.secret }).admission.storage).toEqual(A)
    })

    it('are re-serialised in the fixed key order, so a reordered body is refused', async () => {
      const f = fixture(), event = f.invite({ relays: ['wss://fixed.example/'], storage: A })
      const key = hkdf(sha256, f.host.invitation.bearer, undefined, PERSISTENT_INVITATION_LABELS[0], 32)
      try {
        const body = JSON.parse(nip44.v2.decrypt(event.content, key))
        const { storage, relays, ...rest } = body
        const bad = finalizeEvent({ ...event, content: nip44.v2.encrypt(JSON.stringify({ ...rest, storage, relays }), key) }, f.host.inviterSk)
        const result = await query({ transport: replay([bad]).transport, invitation: f.host.invitation })
        expect(result.outcome).toMatchObject({ status: 'held', reason: 'unavailable' })
      } finally { key.fill(0) }
    })

    it('a plain copy and a copy with nodes admit with the nodes, naming only the copy that carried them', async () => {
      const f = fixture(), plain = f.invite({ now: now - 1 }), listed = f.invite({ storage: A })
      for (const events of [[plain, listed], [listed, plain]]) {
        const result = await query({ transport: replay(events).transport, invitation: f.host.invitation })
        expect(result.outcome.status).toBe('admitted')
        if (result.outcome.status !== 'admitted') throw new Error('held')
        expect(result.outcome.admission.storage).toEqual(A)
        expect(result.outcome.admission.storageAt).toBe(now)
        expect(result.outcome.contributors.storage).toEqual([listed.id])
        expect(result.outcome.contributors.room).toHaveLength(2)
      }
      // A plain copy newer than the list leaves it standing, as for the relays.
      const later = f.invite({ now: now + 5 })
      const result = await query({ transport: replay([listed, later]).transport, invitation: f.host.invitation })
      expect(result.outcome).toMatchObject({ status: 'admitted', admission: { storage: A, storageAt: now } })
    })

    it('the newest copy that names them stands, `[]` included, and they merge apart from the relays', async () => {
      const f = fixture()
      const old = f.invite({ relays: ['wss://old.example/'], storage: A })
      const withRelays = f.invite({ now: now + 1, relays: ['wss://new.example/'] })
      const newer = f.invite({ now: now + 2, storage: B })
      const empty = f.invite({ now: now + 3, storage: [] })
      for (const events of [[old, withRelays, newer], [newer, withRelays, old]]) {
        const result = await query({ transport: replay(events).transport, invitation: f.host.invitation })
        if (result.outcome.status !== 'admitted') throw new Error('held')
        expect(result.outcome.admission).toMatchObject({ relays: ['wss://new.example/'], storage: B, storageAt: now + 2 })
        expect(result.outcome.contributors.relays).toEqual([withRelays.id])
        expect(result.outcome.contributors.storage).toEqual([newer.id])
      }
      for (const events of [[old, newer, empty], [empty, newer, old]]) {
        const result = await query({ transport: replay(events).transport, invitation: f.host.invitation })
        expect(result.outcome).toMatchObject({ status: 'admitted', admission: { storage: [], storageAt: now + 3 } })
      }
    })

    it('holds equal-time newest differing lists deterministically; the legacy request keeps the first heard', async () => {
      const f = fixture(), a = f.invite({ storage: A }), b = f.invite({ storage: B })
      for (const events of [[a, b], [b, a]]) {
        const result = await query({ transport: replay(events).transport, invitation: f.host.invitation })
        expect(result.outcome).toEqual({ status: 'held', reason: 'conflicting-storage', retirementEventIds: [] })
        expect(result.evidence.events).toHaveLength(2)
        const legacy = await requestPersistentRoomAdmission({ transport: replay(events).transport, invitation: f.host.invitation })
        expect(legacy.storage).toEqual(events[0] === a ? A : B)
      }
      // `[]` against a list in one second is a disagreement too.
      const empty = f.invite({ storage: [] })
      expect((await query({ transport: replay([a, empty]).transport, invitation: f.host.invitation })).outcome).toMatchObject({ status: 'held', reason: 'conflicting-storage' })
    })

    it('accepts same-time identical lists, and a strictly newer list supersedes a tie', async () => {
      const f = fixture(), a = f.invite({ storage: A }), twin = f.invite({ storage: A, destruct: true }), other = f.invite({ storage: B }), next = f.invite({ now: now + 1, storage: ['https://next.example.net'] })
      for (const events of [[a, twin], [a, other, next], [next, other, a]]) {
        expect((await query({ transport: replay(events).transport, invitation: f.host.invitation })).outcome.status).toBe('admitted')
      }
    })
  })

  it('accepts same-time identical lists and allows a strictly newer list to supersede an old tie', async () => {
    const f = fixture(), a = f.invite({ relays: ['wss://a.example/'] }), b = f.invite({ relays: ['wss://a.example/'], destruct: true }), c = f.invite({ relays: ['wss://b.example/'] }), next = f.invite({ now: now + 1, relays: ['wss://next.example/'] })
    for (const events of [[a, b], [a, c, next], [next, c, a]]) {
      const result = await query({ transport: replay(events).transport, invitation: f.host.invitation })
      expect(result.outcome.status).toBe('admitted')
    }
  })

  it('retains every observed retirement and refuses without an admission', async () => {
    const f = fixture(), event = f.invite(), retirement = encodeInvitationRetirement({ ...f.host, now: now + 1, ended: true, destruct: true })
    for (const events of [[event, retirement], [retirement, event]]) {
      const result = await query({ transport: replay(events).transport, invitation: f.host.invitation })
      expect(result.outcome).toEqual({ status: 'held', reason: 'retired', retirementEventIds: [retirement.id] })
      expect(result.evidence.eventIds).toEqual([event.id, retirement.id].sort())
      expect('admission' in result.outcome).toBe(false)
      expect(validate({ evidence: result.evidence, invitation: f.host.invitation }).outcome.status).toBe('held')
    }
  })

  it('holds conflicting room roots and binds an exact expected root', async () => {
    const f = fixture(), event = f.invite(), other = f.invite({ roomSecret: new Uint8Array(32).fill(9) })
    const conflict = await query({ transport: replay([event, other]).transport, invitation: f.host.invitation })
    expect(conflict.outcome).toMatchObject({ status: 'held', reason: 'conflicting-rooms' })
    const accepted = await query({ transport: replay([event]).transport, invitation: f.host.invitation })
    expect(validate({ evidence: accepted.evidence, invitation: f.host.invitation, expectedRoomSecret: new Uint8Array(32).fill(9) }).outcome).toMatchObject({ status: 'held', reason: 'wrong-room' })
  })

  it('deduplicates exact carriers and drops a contradictory duplicate ID, ignoring forged verifier cache', async () => {
    const f = fixture(), event = f.invite()
    expect((await query({ transport: replay([event, { ...event }]).transport, invitation: f.host.invitation })).evidence.events).toHaveLength(1)
    const changed = { ...event, content: event.content + 'A', [verifiedSymbol]: true }
    const spy = vi.spyOn(verifier, 'verifyEventUncached')
    try {
      for (const order of [[event, changed], [changed, event]]) {
        spy.mockClear()
        const result = await query({ transport: replay(order).transport, invitation: f.host.invitation })
        expect(result.evidence.eventIds).toEqual([event.id])
        expect(result.evidence.events[0]).toBe(JSON.stringify({ id: event.id, pubkey: event.pubkey, created_at: event.created_at, kind: event.kind, tags: event.tags, content: event.content, sig: event.sig }))
        expect(result.outcome.status).toBe('admitted')
      }
    } finally { spy.mockRestore() }
    const result = await query({ transport: replay([changed]).transport, invitation: f.host.invitation })
    expect(result.outcome).toMatchObject({ status: 'held', reason: 'unavailable' })
  })

  it('does not accept wrong inviter or bearer, and never accepts a partial query', async () => {
    const f = fixture(), event = f.invite(), bad = finalizeEvent({ ...event }, generateSecretKey())
    expect((await query({ transport: replay([bad]).transport, invitation: f.host.invitation })).outcome).toMatchObject({ status: 'held', reason: 'unavailable' })
    const error = await query({ transport: replay([event], false).transport, invitation: f.host.invitation, timeoutMs: 5 }).catch(e => e)
    expect(error).toBeInstanceOf(PersistentInvitationEvidenceQueryError)
    expect(error.observation.completion).toBe('incomplete')
    expect(error.observation.events).toHaveLength(1)
    expect(() => validate({ evidence: error.observation, invitation: f.host.invitation })).toThrow('completion')
    const result = await query({ transport: replay([event]).transport, invitation: f.host.invitation })
    expect(() => validate({ evidence: result.evidence, invitation: { ...f.host.invitation, bearer: new Uint8Array(32).fill(1) } })).toThrow('binding')
  })

  it('bounds count before retaining another event and never evicts or resolves a truncated set', async () => {
    const f = fixture(), events = Array.from({ length: MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS + 1 }, (_, i) => f.invite({ now: now + i }))
    const max = await query({ transport: replay(events.slice(0, -1)).transport, invitation: f.host.invitation })
    expect(max.evidence.events).toHaveLength(64)
    const error = await query({ transport: replay(events).transport, invitation: f.host.invitation }).catch(e => e)
    expect(error).toBeInstanceOf(PersistentInvitationEvidenceQueryError)
    expect(error.message).toContain('capacity')
    expect(error.observation.completion).toBe('incomplete')
    expect(error.observation.events).toHaveLength(64)
  })

  it('bounds aggregate bytes and per-event bytes before yielding evidence', async () => {
    const f = fixture()
    const events = Array.from({ length: 30 }, (_, i) => encodeInvitationRetirement({ ...f.host, now: now + i }))
      .map(event => finalizeEvent({ ...event, content: JSON.stringify({ v: 1, retainedDiagnostic: 'x'.repeat(12_000) }) }, f.host.inviterSk))
    const error = await query({ transport: replay(events).transport, invitation: f.host.invitation }).catch(e => e)
    expect(error.message).toContain('capacity')
    expect(error.observation.events.length).toBeLessThan(events.length)
    // An oversized carrier is not evidence, but it no longer fails the query.
    const huge = { ...f.invite(), content: 'x'.repeat(16_385) }
    expect((await query({ transport: replay([huge]).transport, invitation: f.host.invitation })).outcome).toMatchObject({ status: 'held', reason: 'unavailable' })
  })

  it('charges every delivery before parsing or crypto and never inspects delivery 513', async () => {
    const f = fixture(), event = f.invite()
    const invalid = { ...event, sig: '0'.repeat(128) }
    let touched = 0
    const untouched = new Proxy({}, { get() { touched++; return undefined }, getPrototypeOf() { touched++; return null }, ownKeys() { touched++; return [] },
      getOwnPropertyDescriptor() { touched++; return undefined }, has() { touched++; return false } })
    const spy = vi.spyOn(verifier, 'verifyEventUncached')
    try {
      const error = await query({ transport: replay([...Array(MAX_PERSISTENT_INVITATION_EVIDENCE_DELIVERIES).fill(invalid), untouched]).transport, invitation: f.host.invitation }).catch(e => e)
      expect(error.message).toContain('capacity')
      expect(error.message).toContain('deliveries')
      expect(touched).toBe(0)
      expect(error.observation.completion).toBe('incomplete')
      expect(error.observation.events).toEqual([])
      // One refused carrier repeated 512 times is checked once.
      expect(spy).toHaveBeenCalledTimes(1)
    } finally { spy.mockRestore() }
  })

  it('bounds signature checks and never inspects the one past the bound', async () => {
    const f = fixture(), event = f.invite()
    const forged = Array.from({ length: MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS + 1 }, (_, i) => ({ ...event, created_at: now + i, sig: '0'.repeat(128) }))
    const spy = vi.spyOn(verifier, 'verifyEventUncached')
    try {
      const error = await query({ transport: replay([...forged, event]).transport, invitation: f.host.invitation }).catch(e => e)
      expect(error.message).toContain('capacity')
      expect(error.message).toContain('signature checks')
      expect(error.observation.events).toEqual([])
      expect(spy).toHaveBeenCalledTimes(MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS)
      // At the bound it still admits, with a real copy last. The spy also sees
      // the final revalidation of the one retained event.
      spy.mockClear()
      const ok = await query({ transport: replay([...forged.slice(0, MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS - 1), event]).transport, invitation: f.host.invitation })
      expect(ok.outcome.status).toBe('admitted')
      expect(spy).toHaveBeenCalledTimes(MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS + 1)
    } finally { spy.mockRestore() }
  })

  describe('deliveries are not retained events', () => {
    const foreign = (f: ReturnType<typeof fixture>, n: number, kind = 1463) => Array.from({ length: n }, (_, i) =>
      finalizeEvent({ kind, created_at: now + i, tags: [['d', deriveInvitationId(f.host.invitation)]], content: 'x' }, generateSecretKey()))

    it('65 deliveries of one event admit it once', async () => {
      const f = fixture(), event = f.invite()
      const result = await query({ transport: replay(Array(MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS + 1).fill(event)).transport, invitation: f.host.invitation })
      expect(result.outcome.status).toBe('admitted')
      expect(result.evidence.eventIds).toEqual([event.id])
    })

    it('64 events by another author beside a real copy admit without touching crypto for them', async () => {
      const f = fixture(), event = f.invite(), spy = vi.spyOn(verifier, 'verifyEventUncached')
      try {
        const result = await query({ transport: replay([...foreign(f, MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS), event]).transport, invitation: f.host.invitation })
        expect(result.outcome.status).toBe('admitted')
        expect(result.evidence.eventIds).toEqual([event.id])
        expect(spy).toHaveBeenCalledTimes(2) // the real copy: once in the query, once in revalidation
      } finally { spy.mockRestore() }
    })

    it('drops events of the right author with the wrong kind, no d tag or two d tags, without crypto', async () => {
      const f = fixture(), event = f.invite(), id = deriveInvitationId(f.host.invitation), spy = vi.spyOn(verifier, 'verifyEventUncached')
      const own = (kind: number, tags: string[][]) => finalizeEvent({ kind, created_at: now, tags, content: 'x' }, f.host.inviterSk)
      try {
        const result = await query({ transport: replay([own(1, [['d', id]]), own(1463, []), own(1463, [['d', id], ['d', id]]), own(1463, [['d', 'other']]), own(1463, [['d', id, 'extra']]), event]).transport, invitation: f.host.invitation })
        expect(result.outcome.status).toBe('admitted')
        expect(result.evidence.eventIds).toEqual([event.id])
        expect(spy).toHaveBeenCalledTimes(2) // the real copy: once in the query, once in revalidation
      } finally { spy.mockRestore() }
    })

    it('4 relays each delivering 17 distinct authority copies admit all 17', async () => {
      const f = fixture(), copies = Array.from({ length: 17 }, (_, i) => f.invite({ now: now + i }))
      const spy = vi.spyOn(verifier, 'verifyEventUncached')
      try {
        const result = await query({ transport: replay(Array.from({ length: 4 }, () => copies).flat()).transport, invitation: f.host.invitation })
        expect(result.outcome.status).toBe('admitted')
        expect(result.evidence.eventIds).toHaveLength(17)
        expect(new Set(result.evidence.eventIds)).toEqual(new Set(copies.map(e => e.id)))
        expect(spy).toHaveBeenCalledTimes(34) // 17 in the query, 17 in revalidation: repeats cost nothing
      } finally { spy.mockRestore() }
    })

    it('64 distinct authority copies on each of 8 relays (512 deliveries) still admit all 64', async () => {
      const f = fixture(), copies = Array.from({ length: MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS }, (_, i) => f.invite({ now: now + i }))
      const result = await query({ transport: replay(Array.from({ length: 8 }, () => copies).flat()).transport, invitation: f.host.invitation })
      expect(result.evidence.eventIds).toHaveLength(MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS)
      expect(result.outcome.status).toBe('admitted')
    })

    it('one oversized or malformed event beside a real copy admits', async () => {
      const f = fixture(), event = f.invite()
      const junk = [{ ...event, content: 'x'.repeat(16_385) }, { ...event, tags: 'not tags' }, { ...event, extra: 1 }, null, 'text', 7, Object.create({ unexpectedPrototype: true })]
      const result = await query({ transport: replay([...junk as Event[], event]).transport, invitation: f.host.invitation })
      expect(result.outcome.status).toBe('admitted')
      expect(result.evidence.eventIds).toEqual([event.id])
    })

    it('a forged copy of a real event id does not shadow the real one, in either order', async () => {
      const f = fixture(), event = f.invite(), forged = { ...event, sig: '0'.repeat(128) }
      for (const order of [[forged, event], [event, forged]]) {
        const result = await query({ transport: replay(order).transport, invitation: f.host.invitation })
        expect(result.evidence.events).toEqual([JSON.stringify({ id: event.id, pubkey: event.pubkey, created_at: event.created_at, kind: event.kind, tags: event.tags, content: event.content, sig: event.sig })])
      }
    })

    it('a retirement among junk and repeats is still retained and holds', async () => {
      const f = fixture(), retirement = encodeInvitationRetirement({ ...f.host, now }), event = f.invite()
      const result = await query({ transport: replay([...foreign(f, 100), { ...retirement, sig: '0'.repeat(128) }, event, retirement, retirement]).transport, invitation: f.host.invitation })
      expect(result.outcome).toMatchObject({ status: 'held', reason: 'retired', retirementEventIds: [retirement.id] })
    })

    it('more deliveries than the bound fails closed with a clear message and observation', async () => {
      const f = fixture(), event = f.invite()
      const error = await query({ transport: replay([event, ...foreign(f, MAX_PERSISTENT_INVITATION_EVIDENCE_DELIVERIES)]).transport, invitation: f.host.invitation }).catch(e => e)
      expect(error).toBeInstanceOf(PersistentInvitationEvidenceQueryError)
      expect(error.message).toBe('invitation evidence query capacity exceeded: too many deliveries')
      expect(error.observation.completion).toBe('incomplete')
      expect(error.observation.eventIds).toEqual([event.id])
    }, 30_000) // signs about 512 foreign events, which is slow on a loaded machine

    it('exactly the delivery bound is accepted', async () => {
      const f = fixture(), event = f.invite()
      const result = await query({ transport: replay([...foreign(f, MAX_PERSISTENT_INVITATION_EVIDENCE_DELIVERIES - 1), event]).transport, invitation: f.host.invitation })
      expect(result.outcome.status).toBe('admitted')
    }, 30_000) // signs about 512 foreign events, which is slow on a loaded machine

    it('a 65th unique valid authority event still fails closed, however many repeats and strangers surround it', async () => {
      const f = fixture(), copies = Array.from({ length: MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS + 1 }, (_, i) => f.invite({ now: now + i }))
      const error = await query({ transport: replay([...copies.slice(0, 64), ...copies.slice(0, 64), ...foreign(f, 10), copies[64]!]).transport, invitation: f.host.invitation }).catch(e => e)
      expect(error).toBeInstanceOf(PersistentInvitationEvidenceQueryError)
      expect(error.message).toBe('invitation evidence query capacity exceeded')
      expect(error.observation.events).toHaveLength(MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS)
    })

    it('a valid authority event that would pass 256 KiB retained fails closed, and junk bytes never count', async () => {
      const f = fixture()
      const big = (i: number) => finalizeEvent({ ...encodeInvitationRetirement({ ...f.host, now: now + i }), content: JSON.stringify({ v: 1, retainedDiagnostic: 'x'.repeat(12_000) }) }, f.host.inviterSk)
      const events = Array.from({ length: 30 }, (_, i) => big(i))
      const fit = Math.floor(MAX_PERSISTENT_INVITATION_EVIDENCE_BYTES / (JSON.stringify(events[0]).length + 40))
      const junk = foreign(f, 100).map(e => ({ ...e, content: 'x'.repeat(16_000) }))
      const ok = await query({ transport: replay([...junk, ...events.slice(0, fit - 2)]).transport, invitation: f.host.invitation })
      expect(ok.evidence.events).toHaveLength(fit - 2)
      const error = await query({ transport: replay(events).transport, invitation: f.host.invitation }).catch(e => e)
      expect(error.message).toBe('invitation evidence query capacity exceeded')
      expect(error.observation.events.length).toBeLessThan(events.length)
    })

    describe('events over the evidence size limits', () => {
      /** Signed by the authority with a body and tags the strict carrier refuses. */
      const signed = (f: ReturnType<typeof fixture>, kind: 'invitation' | 'retirement', fault: 'bytes' | 'tags' | 'width', at = now + 5) => {
        const base = kind === 'invitation' ? f.invite({ now: at }) : encodeInvitationRetirement({ ...f.host, now: at })
        const relays = Array.from({ length: 8 }, (_, i) => `wss://r${i}.example.net/${'a'.repeat(1_500)}`)
        let content = base.content, tags = base.tags
        if (fault === 'bytes') content = kind === 'invitation' ? nip44.v2.encrypt(JSON.stringify({ v: 3, relays }), hkdf(sha256, f.host.invitation.bearer, undefined, PERSISTENT_INVITATION_LABELS[0], 32)) : JSON.stringify({ v: 1, note: 'x'.repeat(17_000) })
        if (fault === 'tags') tags = [...tags, ...Array.from({ length: 65 }, (_, i) => ['t', String(i)])]
        if (fault === 'width') tags = [...tags, ['t', '1', '2', '3', '4', '5', '6', '7', '8']]
        return finalizeEvent({ kind: base.kind, created_at: at, tags, content }, f.host.inviterSk)
      }
      const old = (f: ReturnType<typeof fixture>) => f.invite({ now, relays: ['wss://old.example/'] })

      it.each([['invitation', 'bytes'], ['invitation', 'tags'], ['invitation', 'width'], ['retirement', 'bytes'], ['retirement', 'tags'], ['retirement', 'width']] as const)(
        'a validly signed over-limit %s (%s) fails the query rather than being skipped', async (kind, fault) => {
          const f = fixture(), over = signed(f, kind, fault)
          expect(JSON.stringify(over).length > 16_384 || over.tags.length > 64 || over.tags.some(t => t.length > 8)).toBe(true)
          for (const order of [[old(f), over], [over, old(f)]]) {
            const error = await query({ transport: replay(order).transport, invitation: f.host.invitation }).catch(e => e)
            expect(error).toBeInstanceOf(PersistentInvitationEvidenceQueryError)
            expect(error.message).toBe('invitation evidence query refused an event signed by the authority that exceeds the evidence size limits')
            expect(error.observation.completion).toBe('incomplete')
          }
        })

      it('a forged over-limit event claiming the authority is dropped and costs one check, however often repeated', async () => {
        const f = fixture(), real = f.invite(), forged = { ...signed(f, 'invitation', 'bytes'), sig: '0'.repeat(128) }, spy = vi.spyOn(verifier, 'verifyEventUncached')
        try {
          const result = await query({ transport: replay([forged, forged, { ...forged }, real, forged]).transport, invitation: f.host.invitation })
          expect(result.outcome.status).toBe('admitted')
          expect(result.evidence.eventIds).toEqual([real.id])
          expect(spy).toHaveBeenCalledTimes(3) // forged once, real once, revalidation once
        } finally { spy.mockRestore() }
      })

      it('a tampered over-limit copy with the real id and signature cannot mask the real event, and a repeat of it costs nothing', async () => {
        const f = fixture(), real = signed(f, 'invitation', 'bytes'), tampered = { ...real, content: real.content + 'A' }, spy = vi.spyOn(verifier, 'verifyEventUncached')
        try {
          const error = await query({ transport: replay([tampered, tampered, { ...tampered }, real]).transport, invitation: f.host.invitation }).catch(e => e)
          expect(error.message).toBe('invitation evidence query refused an event signed by the authority that exceeds the evidence size limits')
          expect(spy).toHaveBeenCalledTimes(2) // tampered once, real once
        } finally { spy.mockRestore() }
      })

      it('a tampered in-limit copy with the real id and signature cannot mask the real event', async () => {
        const f = fixture(), real = f.invite(), tampered = { ...real, content: real.content + 'A' }, spy = vi.spyOn(verifier, 'verifyEventUncached')
        try {
          const result = await query({ transport: replay([tampered, tampered, real]).transport, invitation: f.host.invitation })
          expect(result.outcome.status).toBe('admitted')
          expect(result.evidence.eventIds).toEqual([real.id])
          expect(spy).toHaveBeenCalledTimes(3) // tampered once, real once, revalidation once
        } finally { spy.mockRestore() }
      })

      it('an over-limit event that is out of scope costs no check', async () => {
        const f = fixture(), real = f.invite(), spy = vi.spyOn(verifier, 'verifyEventUncached')
        const stranger = finalizeEvent({ kind: 1463, created_at: now, tags: [['d', deriveInvitationId(f.host.invitation)]], content: 'x'.repeat(17_000) }, generateSecretKey())
        const wrongKind = finalizeEvent({ kind: 1, created_at: now, tags: [['d', deriveInvitationId(f.host.invitation)]], content: 'x'.repeat(17_000) }, f.host.inviterSk)
        try {
          expect((await query({ transport: replay([stranger, wrongKind, real]).transport, invitation: f.host.invitation })).outcome.status).toBe('admitted')
          expect(spy).toHaveBeenCalledTimes(2)
        } finally { spy.mockRestore() }
      })

      it('malformed beyond size (a getter, a bad hex id) is still dropped without crypto', async () => {
        const f = fixture(), real = f.invite(), spy = vi.spyOn(verifier, 'verifyEventUncached'), over = signed(f, 'invitation', 'bytes')
        try {
          const result = await query({ transport: replay([{ ...over, id: 'zz' }, Object.defineProperty({ ...over }, 'content', { get: () => 'x' }), { ...over, extra: 1 } as Event, real]).transport, invitation: f.host.invitation })
          expect(result.outcome.status).toBe('admitted')
          expect(spy).toHaveBeenCalledTimes(2)
        } finally { spy.mockRestore() }
      })

      it('a stream of forged over-limit events is held to the signature-check bound', async () => {
        const f = fixture(), real = f.invite(), base = signed(f, 'invitation', 'bytes')
        const forged = Array.from({ length: MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS + 1 }, (_, i) => ({ ...base, created_at: now + i, sig: i.toString(16).padStart(128, '0') }))
        const spy = vi.spyOn(verifier, 'verifyEventUncached')
        try {
          const error = await query({ transport: replay([...forged, real]).transport, invitation: f.host.invitation }).catch(e => e)
          expect(error.message).toContain('signature checks')
          expect(spy).toHaveBeenCalledTimes(MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS)
          spy.mockClear()
          const ok = await query({ transport: replay([...forged.slice(0, MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS - 1), real]).transport, invitation: f.host.invitation })
          expect(ok.outcome.status).toBe('admitted')
        } finally { spy.mockRestore() }
      })
    })

    it('erases the decoded secret of every checked event, including the one refused for capacity', async () => {
      const f = fixture(), copies = Array.from({ length: MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS + 1 }, (_, i) => f.invite({ now: now + i }))
      const derive = vi.spyOn(roomModule, 'deriveRoom')
      try {
        const error = await query({ transport: replay(copies).transport, invitation: f.host.invitation }).catch(e => e)
        expect(error.message).toBe('invitation evidence query capacity exceeded')
        const secrets = derive.mock.calls.map(call => call[0] as Uint8Array)
        expect(secrets.length).toBe(MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS + 1)
        for (const secret of secrets) expect(secret.every(b => b === 0)).toBe(true)
      } finally { derive.mockRestore() }
    })

    it('evidence produced by the unchanged format revalidates identically', async () => {
      const f = fixture(), a = f.invite({ now, relays: ['wss://a.example/'] }), b = f.invite({ now: now + 1, endsAt: now + 100 })
      const result = await query({ transport: replay([a, b, a, ...foreign(f, 3)]).transport, invitation: f.host.invitation })
      const stored = JSON.parse(JSON.stringify(result.evidence))
      const again = validate({ evidence: stored, invitation: f.host.invitation })
      expect(again.evidence).toEqual(result.evidence)
      expect(again.outcome).toEqual(result.outcome)
      // Hand-built from the documented format, without the query.
      const events = [a, b].map(e => JSON.stringify({ id: e.id, pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content, sig: e.sig }))
      const ids = [a.id, b.id]
      const sorted = ids.map((id, i) => [id, events[i]!] as const).sort((x, y) => x[0] < y[0] ? -1 : 1)
      const manual = validate({ evidence: { version: 1, invitationId: deriveInvitationId(f.host.invitation), inviter: f.host.invitation.inviter, completion: 'eose', eventIds: sorted.map(x => x[0]), events: sorted.map(x => x[1]) }, invitation: f.host.invitation })
      expect(manual.outcome).toEqual(result.outcome)
      expect(manual.evidence).toEqual(result.evidence)
    })
  })

  describe('the encoder refuses what the strict reader must refuse', () => {
    const relays = (length: number) => Array.from({ length: 8 }, (_, i) => `wss://r${i}.example.net/${'a'.repeat(length)}`)
    it('throws for eight long relays, naming the limit', () => {
      const f = fixture()
      expect(() => f.invite({ relays: relays(1_500) })).toThrow(/over the 16384 a strict reader accepts/)
    })
    it('still signs the largest list that fits, and the query retains it', async () => {
      const f = fixture()
      let low = 0, high = 1_500
      while (low + 1 < high) { const mid = (low + high) >> 1; try { f.invite({ relays: relays(mid) }); low = mid } catch { high = mid } }
      const event = f.invite({ relays: relays(low) })
      expect(new TextEncoder().encode(JSON.stringify(event)).length).toBeLessThanOrEqual(16_384)
      expect(() => f.invite({ relays: relays(high) })).toThrow('strict reader')
      expect((await query({ transport: replay([event]).transport, invitation: f.host.invitation })).outcome.status).toBe('admitted')
    })
  })

  it('refuses UTF-8 and JSON escaping overflow before canonical serialisation or reload parsing', async () => {
    const f = fixture(), event = f.invite()
    for (const text of ['界'.repeat(6_000), String.fromCharCode(0xd800).repeat(3_000), '\u0000'.repeat(3_000)]) {
      const original = { ...event, content: text }
      const stringify = vi.spyOn(JSON, 'stringify')
      let result
      try {
        result = await query({ transport: replay([original]).transport, invitation: f.host.invitation })
        expect(stringify.mock.calls.some(call => call[0] === original || (call[0] as Event)?.content === text)).toBe(false)
      } finally { stringify.mockRestore() }
      // Dropped as an oversized carrier, not retained, and not a failure.
      expect(result.evidence.events).toEqual([])
    }
    // A correct d tag beside an oversized second tag: in scope, over the size limit, forged.
    // It is dropped for that reason (one check charged), never serialised, never retained.
    const spy = vi.spyOn(verifier, 'verifyEventUncached'), stringify = vi.spyOn(JSON, 'stringify')
    try {
      const big = { ...event, tags: [event.tags[0]!, ['x', '界'.repeat(6_000)]] }
      expect((await query({ transport: replay([big]).transport, invitation: f.host.invitation })).evidence.events).toEqual([])
      expect(spy).toHaveBeenCalledTimes(1)
      expect(stringify.mock.calls.some(call => call[0] === big || (call[0] as Event)?.tags === big.tags)).toBe(false)
    } finally { spy.mockRestore(); stringify.mockRestore() }
    const accepted = await query({ transport: replay([event]).transport, invitation: f.host.invitation })
    const parse = vi.spyOn(JSON, 'parse')
    try {
      expect(() => validate({ evidence: { ...accepted.evidence, events: ['界'.repeat(6_000)] }, invitation: f.host.invitation })).toThrow('oversized')
      expect(parse).not.toHaveBeenCalled()
    } finally { parse.mockRestore() }
  })

  it('rejects every supplied malformed runtime root pin instead of disabling it', async () => {
    const f = fixture(), accepted = await query({ transport: replay([f.invite()]).transport, invitation: f.host.invitation })
    for (const pin of [null, false, '', 0, [], new Uint8Array(31), new Uint8Array(33)]) {
      expect(() => validate({ evidence: accepted.evidence, invitation: f.host.invitation, expectedRoomSecret: pin as Uint8Array })).toThrow('expected room root')
    }
  })

  it('accepts the exact canonical UTF-8 byte boundary and refuses the next Unicode increment', async () => {
    const f = fixture(), retirement = encodeInvitationRetirement({ ...f.host, now })
    for (const unit of ['é', '界', '😀', String.fromCharCode(0xd800), '\u0000', '"']) {
      const candidate = (length: number) => finalizeEvent({ ...retirement, content: JSON.stringify({ v: 1, retainedDiagnostic: unit.repeat(length) }) }, f.host.inviterSk)
      const bytes = (event: Event) => new TextEncoder().encode(JSON.stringify({ id: event.id, pubkey: event.pubkey, created_at: event.created_at, kind: event.kind, tags: event.tags, content: event.content, sig: event.sig })).length
      let low = 0, high = 16_384
      // Length is measured independently on real signed carriers, not by
      // the implementation's byte estimator.
      while (low + 1 < high) { const mid = Math.floor((low + high) / 2); if (bytes(candidate(mid)) <= 16_384) low = mid; else high = mid }
      const accepted = await query({ transport: replay([candidate(low)]).transport, invitation: f.host.invitation })
      expect(accepted.outcome).toMatchObject({ status: 'held', reason: 'retired' })
      expect(new TextEncoder().encode(accepted.evidence.events[0]!).length).toBeLessThanOrEqual(16_384)
      // One increment over the limit, validly signed by the authority: it can never be
      // retained, so the query refuses rather than select without it.
      await expect(query({ transport: replay([candidate(high)]).transport, invitation: f.host.invitation })).rejects.toThrow('exceeds the evidence size limits')
    }
  })

  it('rejects non-data event fields without calling getters or trusting prototypes', async () => {
    const f = fixture(), event = f.invite(), getter = vi.fn(() => event.content)
    const dangerous = Object.defineProperty({ ...event }, 'content', { get: getter })
    for (const junk of [dangerous, Object.assign(Object.create({ extra: 1 }), event), { ...event, extra: 1 } as Event]) {
      const result = await query({ transport: replay([junk]).transport, invitation: f.host.invitation })
      expect(result.evidence.events).toEqual([])
    }
    expect(getter).not.toHaveBeenCalled()
  })

  it('rejects modified canonical carriers, event IDs, completion and extra proof fields on reload', async () => {
    const f = fixture(), result = await query({ transport: replay([f.invite()]).transport, invitation: f.host.invitation })
    for (const evidence of [
      { ...result.evidence, completion: 'incomplete' }, { ...result.evidence, extra: true },
      { ...result.evidence, eventIds: ['0'.repeat(64)] },
      { ...result.evidence, events: [result.evidence.events[0] + ' '] },
      { ...result.evidence, events: [JSON.stringify({ ...JSON.parse(result.evidence.events[0]!), sig: '0'.repeat(128) })] },
    ]) expect(() => validate({ evidence, invitation: f.host.invitation })).toThrow()
  })

  it('pins caller invitation before asynchronous relay delivery and unsubscribes on abort', async () => {
    const f = fixture(), event = f.invite(), original = { ...f.host.invitation, bearer: f.host.invitation.bearer.slice() }
    let onEvent!: (event: Event) => void, onEose!: () => void
    const stop = vi.fn(), transport: RelayTransport = { publish: async () => {}, close() {}, subscribe: (_f, e, end) => { onEvent = e; onEose = end!; return stop } }
    const promise = query({ transport, invitation: f.host.invitation })
    f.host.invitation.bearer.fill(0)
    f.host.invitation.inviter = '0'.repeat(64)
    onEvent(event); onEose()
    const result = await promise
    expect(result.evidence.inviter).toBe(original.inviter)
    expect(validate({ evidence: result.evidence, invitation: original }).outcome.status).toBe('admitted')
    const controller = new AbortController(), pending = query({ transport, invitation: original, signal: controller.signal })
    controller.abort()
    await expect(pending).rejects.toThrow('cancelled')
    expect(stop).toHaveBeenCalledTimes(2)
    onEvent(event); onEose()
    expect(stop).toHaveBeenCalledTimes(2)
  })

  it('retains refusal-only partial retirement after lost EOSE and handles subscription/cleanup failure', async () => {
    const f = fixture(), retirement = encodeInvitationRetirement({ ...f.host, now })
    const error = await query({ transport: replay([retirement], false).transport, invitation: f.host.invitation, timeoutMs: 5 }).catch(e => e)
    expect(error.observation.eventIds).toEqual([retirement.id])
    const transport: RelayTransport = { publish: async () => {}, close() {}, subscribe: () => { throw new Error('offline') } }
    await expect(query({ transport, invitation: f.host.invitation })).rejects.toThrow('offline')
    transport.subscribe = (_f, onEvent, onEose) => { onEvent(f.invite()); onEose?.(); return () => { throw new Error('cleanup') } }
    expect((await query({ transport, invitation: f.host.invitation })).outcome.status).toBe('admitted')
  })
})
