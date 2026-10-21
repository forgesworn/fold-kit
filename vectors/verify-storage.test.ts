// Recomputes vectors/storage-vectors.json (see scripts/generate-storage.mjs)
// against `src/` directly: every event a real encoder writes is rebuilt with
// its recorded random draws and must come out byte-identical, every reader is
// the REAL decoder, and every event built by hand is rebuilt from its recorded
// body, nonce and aux-rand. Each body is also opened a second way, with
// nostr-tools' NIP-44 directly, so a bug shared by the generator and `src/`
// cannot round-trip undetected. The 0.13.0 events in `storage-absent` were
// recorded from 0.13.0's own encoder: they are not output of this tree.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { nip44 } from 'nostr-tools'
import { type Event } from 'nostr-tools/pure'
import { finalizeDeterministic, withStubbedRandomness } from './lib/determinism.mjs'
import { roomInvitation } from '../src/invitation.js'
import { isStorageNodeBase, storageNodeFromBase } from '../src/invitation-storage.js'
import { decodePersistentInvitation, encodePersistentInvitation, requestPersistentRoomAdmission, type PersistentRoomAdmission } from '../src/persistent-invitation.js'
import { requestPersistentRoomAdmissionEvidence } from '../src/persistent-invitation-evidence.js'
import type { RelayTransport } from '../src/transport.js'
import { ACCEPTS, REFUSALS } from '../test/storage-fixtures.js'

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, 'storage-vectors.json'), 'utf8'))
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any
const vectors = doc.groups.storage as Any[]
const vec = (name: string): Any => {
  const v = vectors.find((x) => x.name === name)
  if (!v) throw new Error(`no vector ${name}`)
  return v
}
const draws = (randomHex: string[]) => randomHex.map(hexToBytes)
/** The event's own fields, without nostr-tools' verified marker. */
function plain(event: Event): Event {
  const { id, pubkey, created_at, kind, tags, content, sig } = event
  return { id, pubkey, created_at, kind, tags, content, sig } as Event
}
const invitationOf = (i: Any) => roomInvitation(hexToBytes(i.invitation.bearerHex), i.invitation.inviter, true)
const welcomeKey = (bearerHex: string) => hkdf(sha256, hexToBytes(bearerHex), undefined, 'kithmoot/v3/group-invitation-key', 32)
const admission = (a: PersistentRoomAdmission | null) =>
  a && {
    secretHex: bytesToHex(a.secret),
    persistent: a.persistent,
    epoch: a.epoch,
    ...(a.endsAt !== undefined ? { endsAt: a.endsAt } : {}),
    ...(a.relays ? { relays: a.relays } : {}),
    ...(a.destruct ? { destruct: true } : {}),
    ...(a.storage ? { storage: a.storage } : {}),
    ...(a.storageAt !== undefined ? { storageAt: a.storageAt } : {}),
  }
/** The body, opened with nostr-tools directly. */
const bodyOf = (i: Any, event: Event) => nip44.v2.decrypt(event.content, welcomeKey(i.invitation.bearerHex))

/** Rebuild a hand-built event from its recorded body, nonce and aux-rand. */
function rebuild(built: Any, key: Uint8Array, signerSk: Uint8Array): Event {
  const { kind, created_at, tags } = built.event
  const [nonce, aux] = draws(built.randomHex)
  const content = withStubbedRandomness([nonce], () => nip44.v2.encrypt(built.bodyJson, key))
  return finalizeDeterministic({ kind, created_at, tags, content }, signerSk, aux) as Event
}

/** Rebuild an event the real encoder wrote, from its recorded draws. */
function encoded(i: Any, built: Any, options: Record<string, unknown>): Event {
  return plain(withStubbedRandomness(draws(built.randomHex), () =>
    encodePersistentInvitation({ invitation: invitationOf(i), inviterSk: hexToBytes(i.inviterSkHex), roomSecret: hexToBytes(i.roomSecretHex), now: built.event.created_at, ...options })))
}

function replay(events: Event[]): RelayTransport {
  return {
    async publish() {},
    subscribe(_filters, onEvent, onEose) {
      for (const event of events) onEvent(event)
      onEose?.()
      return () => {}
    },
    close() {},
  }
}

const lenient = async (i: Any, events: Event[]) => admission(await requestPersistentRoomAdmission({ transport: replay(events), invitation: invitationOf(i) }))
async function strict(i: Any, events: Event[]) {
  const { outcome } = await requestPersistentRoomAdmissionEvidence({ transport: replay(events), invitation: invitationOf(i) })
  if (outcome.status === 'held') return { status: 'held', reason: outcome.reason, retirementEventIds: [...outcome.retirementEventIds] }
  return { status: 'admitted', admission: admission(outcome.admission), contributors: Object.fromEntries(Object.entries(outcome.contributors).map(([k, v]) => [k, [...v]])) }
}
function copyEvents(i: Any): Record<string, Event> {
  return Object.fromEntries(i.copies.map((c: Any) => [c.name, c.event]))
}

describe('storage-vectors', () => {
  it('is in the KithMoot vector format, with no absolute path in it', () => {
    expect(doc.protocolVersion).toBe('kithmoot/v1')
    expect(doc.generatedBy).toBe('scripts/generate-storage.mjs (forgesworn/fold-kit)')
    expect(JSON.stringify(doc)).not.toMatch(/\/(Users|home|media)\//)
    expect(vectors.map((v) => v.name)).toEqual([
      'storage-invitation', 'storage-full-order', 'storage-withdrawn', 'storage-absent', 'storage-accepts',
      'storage-entry-refusals', 'storage-list-refusals', 'storage-merge', 'storage-relays-independent', 'storage-strict-old-reader',
    ])
    for (const v of vectors) {
      expect(typeof v.name).toBe('string')
      expect(['positive', 'negative']).toContain(v.kind)
      expect(typeof v.note).toBe('string')
      expect(v).toHaveProperty('input')
      expect(v).toHaveProperty('expected')
    }
  })

  it('storage-invitation: the real encoder reproduces it; the list is in the body, last, and never a tag', () => {
    const v = vec('storage-invitation')
    const i = v.input
    expect(encoded(i, i, { storage: i.storage })).toEqual(i.event)
    const body = bodyOf(i, i.event)
    expect(body).toBe(v.expected.bodyJson)
    expect(Object.keys(JSON.parse(body))).toEqual(['v', 'room', 'secret', 'storage'])
    expect(JSON.parse(body).storage).toEqual(['https://grove.example.net'])
    expect(JSON.stringify(i.event.tags)).not.toContain('storage')
    expect(admission(decodePersistentInvitation(i.event, invitationOf(i)))).toEqual(v.expected.admission)
    expect(v.expected.admission).toMatchObject({ storage: ['https://grove.example.net'], storageAt: i.createdAt })
    // A 0.13.0 reader admits the same room, without the list.
    const { storage: _s, storageAt: _a, ...old } = v.expected.admission
    expect(v.expected.oldReader).toEqual(old)
  })

  it('storage-full-order: every optional key, in order', () => {
    const v = vec('storage-full-order')
    const i = v.input
    expect(encoded(i, i, { endsAt: i.endsAt, destruct: true, relays: i.relays, storage: i.storage })).toEqual(i.event)
    const body = bodyOf(i, i.event)
    expect(body).toBe(v.expected.bodyJson)
    expect(Object.keys(JSON.parse(body))).toEqual(['v', 'room', 'secret', 'ends', 'destruct', 'relays', 'storage'])
    expect(JSON.parse(body).storage).toEqual(i.storage)
    expect(i.storage).toHaveLength(3)
    expect(i.event.tags).toEqual([i.event.tags[0], ['expiration', String(i.endsAt)]])
    expect(admission(decodePersistentInvitation(i.event, invitationOf(i)))).toEqual(v.expected.admission)
    expect(v.expected.admission.storage).toEqual(i.storage)
  })

  it('storage-withdrawn: an empty list is a list', () => {
    const v = vec('storage-withdrawn')
    const i = v.input
    expect(encoded(i, i, { storage: [] })).toEqual(i.event)
    expect(bodyOf(i, i.event)).toBe(v.expected.bodyJson)
    expect(v.expected.bodyJson.endsWith(',"storage":[]}')).toBe(true)
    expect(admission(decodePersistentInvitation(i.event, invitationOf(i)))).toEqual(v.expected.admission)
    expect(v.expected.admission).toMatchObject({ storage: [], storageAt: i.createdAt })
  })

  it('storage-absent: today\'s encoder rebuilds what 0.13.0 wrote, byte for byte', () => {
    const v = vec('storage-absent')
    const i = v.input
    expect(encoded(i, i.recorded0130.plain, {})).toEqual(i.recorded0130.plain.event)
    expect(encoded(i, i.recorded0130.full, { endsAt: i.endsAt, destruct: true, relays: i.relays })).toEqual(i.recorded0130.full.event)
    expect(bodyOf(i, i.recorded0130.plain.event)).toBe(v.expected.plainBodyJson)
    expect(bodyOf(i, i.recorded0130.full.event)).toBe(v.expected.fullBodyJson)
    expect(v.expected.plainBodyJson).toBe(`{"v":3,"room":"${i.roomId}","secret":"${JSON.parse(v.expected.plainBodyJson).secret}"}`)
    expect(Object.keys(JSON.parse(v.expected.fullBodyJson))).toEqual(['v', 'room', 'secret', 'ends', 'destruct', 'relays'])
    expect(admission(decodePersistentInvitation(i.recorded0130.plain.event, invitationOf(i)))).toEqual(v.expected.plainAdmission)
    expect(admission(decodePersistentInvitation(i.recorded0130.full.event, invitationOf(i)))).toEqual(v.expected.fullAdmission)
    expect(v.expected.plainAdmission).not.toHaveProperty('storage')
    expect(v.expected.fullAdmission).not.toHaveProperty('storageAt')
  })

  it('storage-accepts: every entry is canonical, names its server and admits', () => {
    const v = vec('storage-accepts')
    const i = v.input
    expect(i.cases.map((c: Any) => [c.entry, c.server])).toEqual(ACCEPTS)
    for (const c of i.cases) {
      expect(plain(rebuild(c, welcomeKey(i.invitation.bearerHex), hexToBytes(i.inviterSkHex)))).toEqual(c.event)
      expect(JSON.parse(bodyOf(i, c.event)).storage).toEqual([c.entry])
      expect(isStorageNodeBase(c.entry)).toBe(true)
      expect(storageNodeFromBase(c.entry)).toEqual({ base: c.entry, server: c.server })
      expect(admission(decodePersistentInvitation(c.event, invitationOf(i)))).toEqual(v.expected.admission[c.entry])
      expect(v.expected.admission[c.entry]?.storage).toEqual([c.entry])
      // The grammar decides, not a parser; but today's Node must agree on each accepted case.
      const u = new URL(c.entry)
      expect(`${u.protocol}//${u.host}${u.pathname === '/' ? '' : u.pathname}`).toBe(c.entry)
    }
    const servers = Object.fromEntries(i.cases.map((c: Any) => [c.entry, c.server]))
    expect(servers['https://xn--bcher-kva.example']).toBe('xn--bcher-kva.example')
    expect(servers['https://xn--a.example.net']).toBe('xn--a.example.net')
    expect(servers['https://0x.example.net']).toBe('0x.example.net')
    expect(servers['https://example.net/WB']).toBe('example.net')
  })

  it('storage-entry-refusals: each is rebuilt exactly and refused outright', () => {
    const v = vec('storage-entry-refusals')
    const i = v.input
    expect(i.cases.map((c: Any) => [c.label, c.entry])).toEqual(REFUSALS)
    expect(i.cases.length).toBeGreaterThanOrEqual(22)
    for (const c of i.cases) {
      expect(plain(rebuild(c, welcomeKey(i.invitation.bearerHex), hexToBytes(i.inviterSkHex)))).toEqual(c.event)
      expect(bodyOf(i, c.event)).toBe(c.bodyJson)
      expect(isStorageNodeBase(c.entry)).toBe(false)
      expect(decodePersistentInvitation(c.event, invitationOf(i))).toBeNull()
      expect(v.expected.admission[c.label]).toBeNull()
      expect(() => encodePersistentInvitation({ invitation: invitationOf(i), inviterSk: hexToBytes(i.inviterSkHex), roomSecret: hexToBytes(i.roomSecretHex), now: 1, storage: [c.entry] }))
        .toThrow(v.expected.encoder[c.label])
      expect(v.expected.encoder[c.label]).toBe(`storage nodes must be canonical node URLs (https, or http only on this machine): ${c.entry}`)
      // A 0.13.0 reader never looks at the key and admits.
      expect(v.expected.oldReader[c.label]).toMatchObject({ persistent: true, epoch: 0 })
      expect(v.expected.oldReader[c.label]).not.toHaveProperty('storage')
    }
  })

  it('storage-list-refusals: each is rebuilt exactly and refused outright; eight is valid', () => {
    const v = vec('storage-list-refusals')
    const i = v.input
    for (const c of i.cases) {
      expect(plain(rebuild(c, welcomeKey(i.invitation.bearerHex), hexToBytes(i.inviterSkHex)))).toEqual(c.event)
      expect(JSON.parse(bodyOf(i, c.event)).storage).toEqual(c.storage)
      expect(decodePersistentInvitation(c.event, invitationOf(i))).toBeNull()
      expect(v.expected.admission[c.label]).toBeNull()
      expect(v.expected.encoder[c.label]).toMatch(/storage node/)
      expect(() => encodePersistentInvitation({ invitation: invitationOf(i), inviterSk: hexToBytes(i.inviterSkHex), roomSecret: hexToBytes(i.roomSecretHex), now: 1, storage: c.storage }))
        .toThrow(v.expected.encoder[c.label])
      expect(v.expected.oldReader[c.label]).toMatchObject({ persistent: true, epoch: 0 })
    }
    expect(i.cases.some((c: Any) => Array.isArray(c.storage) && c.storage.length === 9)).toBe(true)
    expect(i.cases.some((c: Any) => JSON.stringify(c.storage) === JSON.stringify(['http://localhost:3000', 'https://localhost']))).toBe(true)
    expect(v.expected.encoder['one host under two schemes']).toBe('storage nodes must not share a host name: localhost')
    expect(i.eight.storage).toHaveLength(8)
    expect(encoded(i, i.eight, { storage: i.eight.storage })).toEqual(i.eight.event)
    expect(admission(decodePersistentInvitation(i.eight.event, invitationOf(i)))?.storage).toEqual(i.eight.storage)
    expect(v.expected.eight.storage).toEqual(i.eight.storage)
  })

  /** Rebuild every copy with the real encoder from its recorded draws. */
  function checkCopies(i: Any) {
    for (const c of i.copies) {
      expect(encoded(i, c, { ...(c.storage ? { storage: c.storage } : {}), ...(c.relays ? { relays: c.relays } : {}) })).toEqual(c.event)
      const keys = Object.keys(JSON.parse(bodyOf(i, c.event)))
      expect(keys.includes('storage')).toBe(c.storage !== undefined)
    }
  }

  it('storage-merge: the newest copy naming storage stands in every order, `[]` included', async () => {
    const v = vec('storage-merge')
    const i = v.input
    checkCopies(i)
    const events = copyEvents(i)
    const run = async (group: Any) => {
      for (const [order, out] of Object.entries<Any>(group)) {
        const list = order.split(',').map((n) => events[n]!)
        expect(await lenient(i, list)).toEqual(out.lenient)
        expect(await strict(i, list)).toEqual(out.strict)
      }
    }
    await run(v.expected.newest)
    await run(v.expected.withdrawn)
    await run(v.expected.tie)
    await run(v.expected.olderEmptyLoses)
    for (const out of Object.values<Any>(v.expected.newest)) expect(out.lenient).toMatchObject({ storage: i.copies.find((c: Any) => c.name === 'newer').storage, storageAt: i.copies.find((c: Any) => c.name === 'newer').createdAt })
    for (const out of Object.values<Any>(v.expected.withdrawn)) expect(out.lenient).toMatchObject({ storage: [], storageAt: i.copies.find((c: Any) => c.name === 'empty').createdAt })
    // Between copies of one second: first heard (lenient), held (strict).
    expect(v.expected.tie['tie-a,tie-b'].lenient.storage).toEqual(i.copies.find((c: Any) => c.name === 'tie-a').storage)
    expect(v.expected.tie['tie-b,tie-a'].lenient.storage).toEqual(i.copies.find((c: Any) => c.name === 'tie-b').storage)
    for (const out of Object.values<Any>(v.expected.tie)) expect(out.strict).toEqual({ status: 'held', reason: 'conflicting-storage', retirementEventIds: [] })
    // A copy with no key leaves the list alone, whichever order, even when it is the newest.
    for (const out of Object.values<Any>(v.expected.newest)) expect(out.strict.contributors.storage).toEqual([i.copies.find((c: Any) => c.name === 'newer').event.id])
    // An empty list that is older than a list loses.
    for (const out of Object.values<Any>(v.expected.olderEmptyLoses)) expect(out.lenient.storage).toEqual(i.copies.find((c: Any) => c.name === 'newer').storage)
    for (const c of i.copies) expect(admission(decodePersistentInvitation(c.event, invitationOf(i)))).toEqual(v.expected.alone[c.name])
  })

  it('storage-relays-independent: the relays and the nodes come from different copies', async () => {
    const v = vec('storage-relays-independent')
    const i = v.input
    checkCopies(i)
    const events = copyEvents(i)
    for (const [order, out] of Object.entries<Any>(v.expected.orders)) {
      const list = order.split(',').map((n) => events[n])
      expect(await lenient(i, list)).toEqual(out.lenient)
      expect(await strict(i, list)).toEqual(out.strict)
      expect(out.strict.contributors.relays).toEqual([events['ind-b'].id])
      expect(out.strict.contributors.storage).toEqual([events['ind-c'].id])
      expect(out.lenient.relays).toEqual(['wss://new.example.com/'])
      expect(out.lenient.storageAt).toBe(events['ind-c'].created_at)
    }
  })

  it('storage-strict-old-reader: the plain copy is what a 0.13.0 strict reader admits from', async () => {
    const v = vec('storage-strict-old-reader')
    const i = v.input
    checkCopies(i)
    const [plainCopy, withStorage] = i.copies.map((c: Any) => c.event)
    expect(await strict(i, [plainCopy, withStorage])).toEqual(v.expected.strict)
    expect(await strict(i, [withStorage, plainCopy])).toEqual(v.expected.strictReversed)
    expect(await lenient(i, [plainCopy, withStorage])).toEqual(v.expected.lenient)
    expect(v.expected.strict.admission.storage).toEqual(i.copies[1].storage)
    expect(v.expected.strict.admission.storageAt).toBe(i.copies[1].createdAt)
    expect(v.expected.strict.contributors.storage).toEqual([withStorage.id])
    // 0.13.0, recorded: admitted from the plain copy alone, no storage; held when only the storage copy exists.
    expect(v.expected.oldStrictReader).toMatchObject({ status: 'admitted', contributors: { room: [plainCopy.id], relays: [] } })
    expect(v.expected.oldStrictReader.admission).not.toHaveProperty('storage')
    expect(v.expected.oldStrictReaderAlone).toMatchObject({ status: 'held', reason: 'unavailable' })
    // The plain copy has no storage key at all, so 0.13.0 strict can retain it.
    expect(Object.keys(JSON.parse(bodyOf(i, plainCopy)))).toEqual(['v', 'room', 'secret'])
  })
})
