// Recomputes vectors/destruct-vectors.json (see scripts/generate-destruct.mjs
// and docs/room-destruct.md) against `src/` directly: every event a real
// encoder writes is rebuilt with its recorded random draws and must come out
// byte-identical, every reader is the REAL decoder, and every event built by
// hand is rebuilt from its recorded body, nonce and aux-rand. Each body is
// also opened a second way, with nostr-tools' NIP-44 directly, so a bug
// shared by the generator and `src/` cannot round-trip undetected.
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
import { decodeRekeyEvent, deriveEpoch, encodeRekeyEvent } from '../src/epoch.js'
import { decodeInvitationRetirement, decodeInvitationRetirementNotice, encodeInvitationRetirement, roomInvitation } from '../src/invitation.js'
import { readRekeyEvidence } from '../src/member-epoch.js'
import { decodePersistentInvitation, encodePersistentInvitation, requestPersistentRoomAdmission, type PersistentRoomAdmission } from '../src/persistent-invitation.js'
import type { RelayTransport } from '../src/transport.js'

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, 'destruct-vectors.json'), 'utf8'))
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any
const vectors = doc.groups.destruct as Any[]
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
const epochOf = (e: { epoch: number; secretHex: string }) => ({ epoch: e.epoch, secret: hexToBytes(e.secretHex) })
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
  }
const notice = (n: ReturnType<typeof decodeRekeyEvent>) =>
  n && {
    epoch: n.epoch,
    removed: n.removed,
    closed: n.closed,
    ...(n.destruct ? { destruct: true } : {}),
    ...(n.scheduled ? { scheduled: true } : {}),
    ...(n.secret ? { secretHex: bytesToHex(n.secret) } : {}),
    at: n.at,
  }

/** Rebuild a hand-built event from its recorded body, nonce and aux-rand. */
function rebuild(built: Any, key: Uint8Array | null, signerSk: Uint8Array): Event {
  const { kind, created_at, tags } = built.event
  if (!key) return finalizeDeterministic({ kind, created_at, tags, content: built.bodyJson }, signerSk, draws(built.randomHex)[0]) as Event
  const [nonce, aux] = draws(built.randomHex)
  const content = withStubbedRandomness([nonce], () => nip44.v2.encrypt(built.bodyJson, key))
  return finalizeDeterministic({ kind, created_at, tags, content }, signerSk, aux) as Event
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

describe('destruct-vectors', () => {
  it('is in the KithMoot vector format', () => {
    expect(doc.protocolVersion).toBe('kithmoot/v1')
    for (const v of vectors) {
      expect(typeof v.name).toBe('string')
      expect(['positive', 'negative']).toContain(v.kind)
      expect(typeof v.note).toBe('string')
    }
  })

  it('destruct-invitation: the real encoder reproduces it and its 0.8.0 twin, and the flag is only in the body', () => {
    const v = vec('destruct-invitation')
    const i = v.input
    const invitation = invitationOf(i)
    const options = { invitation, inviterSk: hexToBytes(i.inviterSkHex), roomSecret: hexToBytes(i.roomSecretHex), now: i.createdAt, endsAt: i.endsAt, relays: i.relays }
    expect(plain(withStubbedRandomness(draws(i.randomHex), () => encodePersistentInvitation({ ...options, destruct: true })))).toEqual(i.event)
    expect(plain(withStubbedRandomness(draws(i.unflagged.randomHex), () => encodePersistentInvitation(options)))).toEqual(i.unflagged.event)

    const body = nip44.v2.decrypt(i.event.content, welcomeKey(i.invitation.bearerHex))
    expect(body).toBe(v.output.bodyJson)
    expect(Object.keys(JSON.parse(body))).toEqual(['v', 'room', 'secret', 'ends', 'destruct', 'relays'])
    expect(JSON.stringify(i.event.tags)).not.toContain('destruct')
    const unflaggedBody = nip44.v2.decrypt(i.unflagged.event.content, welcomeKey(i.invitation.bearerHex))
    expect(unflaggedBody).toBe(v.output.unflaggedBodyJson)
    expect(unflaggedBody).toBe(body.replace('"destruct":true,', ''))

    expect(admission(decodePersistentInvitation(i.event, invitation))).toEqual(v.output.admission)
    expect(v.output.admission.destruct).toBe(true)
    expect(admission(decodePersistentInvitation(i.unflagged.event, invitation))).toEqual(v.output.unflaggedAdmission)
    expect(v.output.unflaggedAdmission).not.toHaveProperty('destruct')
    // A 0.8.0 reader admits exactly as it would have to the unflagged twin.
    expect(v.output.oldReader).toEqual(v.output.unflaggedAdmission)
  })

  it('destruct-invitation-no-end: the flag needs no end', () => {
    const v = vec('destruct-invitation-no-end')
    const i = v.input
    const invitation = invitationOf(i)
    const event = withStubbedRandomness(draws(i.randomHex), () =>
      encodePersistentInvitation({ invitation, inviterSk: hexToBytes(i.inviterSkHex), roomSecret: hexToBytes(i.roomSecretHex), now: i.createdAt, destruct: true }),
    )
    expect(plain(event)).toEqual(i.event)
    expect(i.event.tags).toHaveLength(1)
    expect(nip44.v2.decrypt(i.event.content, welcomeKey(i.invitation.bearerHex))).toBe(v.output.bodyJson)
    expect(admission(decodePersistentInvitation(i.event, invitation))).toEqual(v.output.admission)
    expect(v.output.admission).toMatchObject({ destruct: true })
    expect(v.output.admission).not.toHaveProperty('endsAt')
  })

  it('destruct-invitation-malformed: each is rebuilt exactly and refused outright', () => {
    const v = vec('destruct-invitation-malformed')
    const i = v.input
    const invitation = invitationOf(i)
    for (const [k, built] of Object.entries<Any>(i.cases)) {
      expect(plain(rebuild(built, welcomeKey(i.invitation.bearerHex), hexToBytes(i.inviterSkHex)))).toEqual(built.event)
      expect(JSON.parse(built.bodyJson).destruct).not.toBe(true)
      expect(decodePersistentInvitation(built.event, invitation)).toBeNull()
      expect(v.output.admission[k]).toBeNull()
      expect(v.output.oldReader[k]).toMatchObject({ persistent: true, epoch: 0 })
    }
  })

  it('destruct-invitation-copies: self-destruct sticks whichever copy is heard first', async () => {
    const v = vec('destruct-invitation-copies')
    const i = v.input
    const invitation = invitationOf(i)
    expect(admission(decodePersistentInvitation(i.older.event, invitation))).toEqual(v.output.alone.older)
    expect(admission(decodePersistentInvitation(i.newer.event, invitation))).toEqual(v.output.alone.newer)
    expect(i.newer.event.created_at).toBeGreaterThan(i.older.event.created_at)
    const admit = async (events: Event[]) => admission(await requestPersistentRoomAdmission({ transport: replay(events), invitation }))
    expect(await admit([i.older.event, i.newer.event])).toEqual(v.output.olderFirst)
    expect(await admit([i.newer.event, i.older.event])).toEqual(v.output.newerFirst)
    expect(v.output.olderFirst).toMatchObject({ destruct: true, relays: v.output.alone.newer.relays })
    expect(v.output.newerFirst).toEqual(v.output.olderFirst)
  })

  it('destruct-retirement: the real encoder reproduces it and its 0.8.0 twin, and both read as ended', () => {
    const v = vec('destruct-retirement')
    const i = v.input
    const invitation = invitationOf(i)
    const options = { invitation, inviterSk: hexToBytes(i.inviterSkHex), now: i.createdAt, ended: true }
    expect(plain(withStubbedRandomness(draws(i.randomHex), () => encodeInvitationRetirement({ ...options, destruct: true })))).toEqual(i.event)
    expect(plain(withStubbedRandomness(draws(i.unflagged.randomHex), () => encodeInvitationRetirement(options)))).toEqual(i.unflagged.event)
    expect(i.event.content).toBe('{"v":1,"ended":true,"destruct":true}')
    expect(i.unflagged.event.content).toBe('{"v":1,"ended":true}')
    expect(JSON.stringify(i.event.tags)).not.toContain('destruct')
    expect(decodeInvitationRetirement(i.event, invitation)).toBe(true)
    expect(decodeInvitationRetirementNotice(i.event, invitation)).toEqual(v.output.notice)
    expect(v.output.notice).toEqual({ ended: true, destruct: true })
    expect(decodeInvitationRetirementNotice(i.unflagged.event, invitation)).toEqual(v.output.unflaggedNotice)
    expect(v.output.oldReader).toEqual({ ended: true })
  })

  it('destruct-retirement-not-ended: refused by the encoder; a reader keeps the retirement and drops the flag', () => {
    const v = vec('destruct-retirement-not-ended')
    const i = v.input
    const invitation = invitationOf(i)
    const inviterSk = hexToBytes(vec('destruct-retirement').input.inviterSkHex)
    expect(plain(rebuild(i, null, inviterSk))).toEqual(i.event)
    expect(() => encodeInvitationRetirement({ invitation, inviterSk, now: i.event.created_at, destruct: true })).toThrow()
    expect(v.output.encoder).toBe('refused')
    expect(decodeInvitationRetirement(i.event, invitation)).toBe(true)
    expect(decodeInvitationRetirementNotice(i.event, invitation)).toEqual(v.output.notice)
    expect(v.output.notice).toEqual({ ended: false })
  })

  it('destruct-closure: the real encoder reproduces it and its 0.8.0 twin, and both readers report the flag', () => {
    const v = vec('destruct-closure')
    const i = v.input
    const previous = deriveEpoch(epochOf(i.previous))
    const options = {
      roomId: i.roomId,
      authoritySk: hexToBytes(i.authoritySkHex),
      current: previous,
      next: epochOf(i.next),
      recipients: i.recipients,
      removed: [],
      closed: true,
      now: i.createdAt,
    }
    expect(plain(withStubbedRandomness(draws(i.randomHex), () => encodeRekeyEvent({ ...options, destruct: true })))).toEqual(i.event)
    expect(plain(withStubbedRandomness(draws(i.unflagged.randomHex), () => encodeRekeyEvent(options)))).toEqual(i.unflagged.event)

    const body = nip44.v2.decrypt(i.event.content, previous.key)
    expect(body).toBe(v.output.bodyJson)
    expect(Object.keys(JSON.parse(body))).toEqual(['v', 'epoch', 'removed', 'closed', 'destruct', 'keys'])
    expect(i.event.tags).toEqual([['d', i.roomId], ['epoch', '2']])
    const unflaggedBody = nip44.v2.decrypt(i.unflagged.event.content, previous.key)
    expect(unflaggedBody).toBe(v.output.unflaggedBodyJson)
    expect(unflaggedBody).toBe(body.replace('"destruct":true,', ''))

    const read = (e: Event) => notice(decodeRekeyEvent(e, { roomId: i.roomId, authority: i.authority, current: previous, deviceSk: hexToBytes(i.deviceSkHex) }))
    expect(read(i.event)).toEqual(v.output.notice)
    expect(v.output.notice).toMatchObject({ closed: true, destruct: true })
    expect(read(i.unflagged.event)).toEqual(v.output.unflaggedNotice)
    expect(v.output.unflaggedNotice).not.toHaveProperty('destruct')
    expect(readRekeyEvidence(i.event, { roomId: i.roomId, authority: i.authority, previous })).toEqual(v.output.evidence)
    expect(v.output.evidence).toMatchObject({ closed: true, destruct: true })
    // A 0.8.0 reader sees the close it always saw.
    expect(v.output.oldReader).toEqual(v.output.unflaggedNotice)
  })

  it('destruct-rekey-open: refused by the encoder; a reader reads the rekey and drops the flag', () => {
    const v = vec('destruct-rekey-open')
    const i = v.input
    const previous = deriveEpoch(epochOf(i.previous))
    const closure = vec('destruct-closure').input
    const authoritySk = hexToBytes(closure.authoritySkHex)
    const base = { roomId: i.roomId, authoritySk, current: previous, next: epochOf(closure.next), recipients: [], removed: [] as string[], now: 0, destruct: true }
    const gone = JSON.parse(i.withRemoval.bodyJson).removed[0]
    expect(() => encodeRekeyEvent({ ...base, removed: [gone] })).toThrow()
    expect(() => encodeRekeyEvent({ ...base, scheduled: true })).toThrow()
    expect(v.output.encoder).toEqual({ withRemoval: 'refused', withScheduled: 'refused' })

    for (const k of ['withRemoval', 'withScheduled']) {
      const built = i[k]
      expect(plain(rebuild(built, previous.key, authoritySk))).toEqual(built.event)
      expect(nip44.v2.decrypt(built.event.content, previous.key)).toBe(built.bodyJson)
      const read = notice(decodeRekeyEvent(built.event, { roomId: i.roomId, authority: i.authority, current: previous, deviceSk: hexToBytes(i.deviceSkHex) }))
      expect(read).toEqual(v.output[k].notice)
      expect(read).not.toHaveProperty('destruct')
      const evidence = readRekeyEvidence(built.event, { roomId: i.roomId, authority: i.authority, previous })
      expect(evidence).toEqual(v.output[k].evidence)
      expect(evidence).not.toHaveProperty('destruct')
    }
    expect(v.output.withRemoval.notice.removed).toEqual([gone])
    expect(v.output.withScheduled.notice.scheduled).toBe(true)
  })
})
