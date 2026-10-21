import { describe, expect, it, vi } from 'vitest'
import { finalizeEvent, generateSecretKey, verifiedSymbol, type Event } from 'nostr-tools/pure'
import { createRoomInvitation, deriveInvitationId, encodeInvitationRetirement } from './invitation.js'
import { encodePersistentInvitation, requestPersistentRoomAdmission } from './persistent-invitation.js'
import { requestPersistentRoomAdmissionEvidence as query, revalidatePersistentInvitationEvidence as validate, revalidatePersistentInvitationSource as revalidateSource,
  PersistentInvitationEvidenceQueryError, MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS } from './persistent-invitation-evidence.js'
import type { RelayTransport } from './transport.js'
import * as verifier from './verify.js'
import { nip44 } from 'nostr-tools'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { PERSISTENT_INVITATION_LABELS } from './persistent-invitation.js'

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
    expect(result.outcome.contributors).toEqual({ room: [event.id], ends: [], destruct: [], relays: [event.id], storage: [] })
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

  it('deduplicates exact carriers but holds a contradictory duplicate ID, ignoring forged verifier cache', async () => {
    const f = fixture(), event = f.invite()
    expect((await query({ transport: replay([event, { ...event }]).transport, invitation: f.host.invitation })).evidence.events).toHaveLength(1)
    const changed = { ...event, content: event.content + 'A', [verifiedSymbol]: true }
    await expect(query({ transport: replay([event, changed]).transport, invitation: f.host.invitation })).rejects.toThrow('conflicting duplicate')
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
    const huge = { ...f.invite(), content: 'x'.repeat(16_385) }
    await expect(query({ transport: replay([huge]).transport, invitation: f.host.invitation })).rejects.toThrow('oversized')
  })

  it('charges invalid candidates before crypto and never inspects candidate 65', async () => {
    const f = fixture(), event = f.invite()
    const invalid = { ...event, sig: '0'.repeat(128) }
    const untouched = Object.create({ unexpectedPrototype: true })
    const spy = vi.spyOn(verifier, 'verifyEventUncached')
    try {
      const error = await query({ transport: replay([...Array(64).fill(invalid), untouched]).transport, invitation: f.host.invitation }).catch(e => e)
      expect(error.message).toContain('capacity')
      expect(error.observation.completion).toBe('incomplete')
      expect(error.observation.events).toEqual([])
      expect(spy).toHaveBeenCalledTimes(64)
    } finally { spy.mockRestore() }
  })

  it('refuses UTF-8 and JSON escaping overflow before canonical serialisation or reload parsing', async () => {
    const f = fixture(), event = f.invite()
    for (const text of ['界'.repeat(6_000), String.fromCharCode(0xd800).repeat(3_000), '\u0000'.repeat(3_000)]) {
      const original = { ...event, content: text }
      const stringify = vi.spyOn(JSON, 'stringify')
      let error
      try {
        error = await query({ transport: replay([original]).transport, invitation: f.host.invitation }).catch(e => e)
        expect(stringify.mock.calls.some(call => call[0] === original || (call[0] as Event)?.content === text)).toBe(false)
      } finally { stringify.mockRestore() }
      expect(error.message).toContain('oversized')
    }
    await expect(query({ transport: replay([{ ...event, tags: [['d', '界'.repeat(6_000)]] }]).transport, invitation: f.host.invitation })).rejects.toThrow('oversized')
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
      await expect(query({ transport: replay([candidate(high)]).transport, invitation: f.host.invitation })).rejects.toThrow('oversized')
    }
  })

  it('rejects non-data event fields without calling getters or trusting prototypes', async () => {
    const f = fixture(), event = f.invite(), getter = vi.fn(() => event.content)
    const dangerous = Object.defineProperty({ ...event }, 'content', { get: getter })
    await expect(query({ transport: replay([dangerous]).transport, invitation: f.host.invitation })).rejects.toThrow('field')
    expect(getter).not.toHaveBeenCalled()
    await expect(query({ transport: replay([Object.assign(Object.create({ extra: 1 }), event)]).transport, invitation: f.host.invitation })).rejects.toThrow('record')
    await expect(query({ transport: replay([{ ...event, extra: 1 } as Event]).transport, invitation: f.host.invitation })).rejects.toThrow('field')
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
