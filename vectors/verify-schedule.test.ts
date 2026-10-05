// Recomputes vectors/schedule-vectors.json (see scripts/generate-schedule.mjs
// and docs/scheduled-rekey.md) against `src/` directly: every event a real
// encoder writes is rebuilt with its recorded random draws and must come out
// byte-identical, every reader is the REAL decoder, and every event built by
// hand is rebuilt from its recorded body, nonce and aux-rand. Each body is
// also opened a second way, with nostr-tools' NIP-44 directly, so a bug
// shared by the generator and `src/` cannot round-trip undetected.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { type Event } from 'nostr-tools/pure'
import { finalizeDeterministic, withStubbedRandomness } from './lib/determinism.mjs'
import {
  HISTORY_WINDOW_SECONDS,
  MAX_HISTORY_EPOCHS,
  decodeEpochGrant,
  decodeRekeyEvent,
  deriveEpoch,
  encodeEpochGrant,
  encodeRekeyEvent,
  epochsInWindow,
} from '../src/epoch.js'
import { epochCommitment } from '../src/epoch-commit.js'
import { readRekeyEvidence } from '../src/member-epoch.js'

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, 'schedule-vectors.json'), 'utf8'))
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any
const vectors = doc.groups.schedule as Any[]
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
const notice = (n: ReturnType<typeof decodeRekeyEvent>) =>
  n && {
    epoch: n.epoch,
    removed: n.removed,
    closed: n.closed,
    ...(n.scheduled ? { scheduled: true } : {}),
    ...(n.members ? { members: n.members } : {}),
    ...(n.secret ? { secretHex: bytesToHex(n.secret) } : {}),
    at: n.at,
  }

/** Rebuild a hand-built event from its recorded body, nonce and aux-rand. */
function rebuild(built: Any, key: Uint8Array, authoritySk: Uint8Array): Event {
  const [nonce, aux] = draws(built.randomHex)
  const content = withStubbedRandomness([nonce], () => nip44.v2.encrypt(built.bodyJson, key))
  const { kind, created_at, tags } = built.event
  return finalizeDeterministic({ kind, created_at, tags, content }, authoritySk, aux) as Event
}

describe('schedule-vectors', () => {
  it('is in the KithMoot vector format', () => {
    expect(doc.protocolVersion).toBe('kithmoot/v1')
    for (const v of vectors) {
      expect(typeof v.name).toBe('string')
      expect(['positive', 'negative']).toContain(v.kind)
      expect(typeof v.note).toBe('string')
    }
  })

  it('scheduled-rekey: the real encoder reproduces it, and it reads as scheduled from the epoch it leaves', () => {
    const v = vec('scheduled-rekey')
    const i = v.input
    const previous = deriveEpoch(epochOf(i.previous))
    const options = {
      roomId: i.roomId,
      authoritySk: hexToBytes(i.authoritySkHex),
      current: previous,
      next: epochOf(i.next),
      recipients: i.recipients,
      removed: [],
      commit: true,
      members: i.members,
      now: i.createdAt,
    }
    const event = withStubbedRandomness(draws(i.randomHex), () => encodeRekeyEvent({ ...options, scheduled: true }))
    expect(plain(event)).toEqual(i.event)
    const unflagged = withStubbedRandomness(draws(i.unflagged.randomHex), () => encodeRekeyEvent(options))
    expect(plain(unflagged)).toEqual(i.unflagged.event)

    // A second way: the marker is in the body, and nowhere on the wire.
    const body = nip44.v2.decrypt(i.event.content, previous.key)
    expect(body).toBe(v.output.bodyJson)
    expect(JSON.parse(body).scheduled).toBe(true)
    expect(i.event.tags).toEqual([['d', i.roomId], ['epoch', '2']])
    const unflaggedBody = nip44.v2.decrypt(i.unflagged.event.content, previous.key)
    expect(unflaggedBody).toBe(v.output.unflaggedBodyJson)
    expect(unflaggedBody).toBe(body.replace('"scheduled":true,', ''))

    const read = (e: Event) => notice(decodeRekeyEvent(e, { roomId: i.roomId, authority: i.authority, current: previous, deviceSk: hexToBytes(i.deviceSkHex) }))
    expect(read(i.event)).toEqual(v.output.notice)
    expect(v.output.notice.scheduled).toBe(true)
    expect(v.output.notice.secretHex).toBe(i.next.secretHex)
    expect(read(i.unflagged.event)).toEqual(v.output.unflaggedNotice)
    expect(v.output.unflaggedNotice.scheduled).toBeUndefined()

    // The chain runs through it: read with the previous epoch's key alone,
    // it checks out, and its commitment matches the secret it carries.
    const evidence = readRekeyEvidence(i.event, { roomId: i.roomId, authority: i.authority, previous })
    expect(evidence).toEqual(v.output.evidence)
    expect(evidence?.commit).toBe(epochCommitment(i.roomId, 2, hexToBytes(i.next.secretHex)))
    expect(v.output.commit).toBe(evidence?.commit)
  })

  it('scheduled-rekey-contradictory: the encoder refuses both, and a reader announces the removal and the close', () => {
    const v = vec('scheduled-rekey-contradictory')
    const i = v.input
    const previous = deriveEpoch(epochOf(i.previous))
    const authoritySk = hexToBytes(vec('scheduled-rekey').input.authoritySkHex)
    const base = {
      roomId: i.roomId,
      authoritySk,
      current: previous,
      next: epochOf(vec('scheduled-rekey').input.next),
      recipients: [],
      removed: [] as string[],
      now: 0,
      scheduled: true,
    }
    const gone = JSON.parse(i.withRemoval.bodyJson).removed[0]
    expect(() => encodeRekeyEvent({ ...base, removed: [gone] })).toThrow()
    expect(() => encodeRekeyEvent({ ...base, closed: true })).toThrow()
    expect(v.output.encoder).toEqual({ withRemoval: 'refused', withClose: 'refused' })

    for (const k of ['withRemoval', 'withClose']) {
      const built = i[k]
      expect(plain(rebuild(built, previous.key, authoritySk))).toEqual(built.event)
      expect(nip44.v2.decrypt(built.event.content, previous.key)).toBe(built.bodyJson)
      expect(JSON.parse(built.bodyJson).scheduled).toBe(true)
      const n = notice(decodeRekeyEvent(built.event, { roomId: i.roomId, authority: i.authority, current: previous, deviceSk: hexToBytes(i.deviceSkHex) }))
      expect(n).toEqual(v.output[k].notice)
      expect(n).not.toBeNull()
      expect(n!.scheduled).toBeUndefined()
      const evidence = readRekeyEvidence(built.event, { roomId: i.roomId, authority: i.authority, previous })
      expect(evidence).toEqual(v.output[k].evidence)
      expect(evidence!.scheduled).toBeUndefined()
    }
    expect(v.output.withRemoval.notice.removed).toHaveLength(1)
    expect(v.output.withClose.notice.closed).toBe(true)
  })

  it('epoch-grant-window: sixteen ride, a seventeenth is refused, and a malformed list costs only itself', () => {
    const v = vec('epoch-grant-window')
    const i = v.input
    const authoritySk = hexToBytes(i.authoritySkHex)
    const deviceSk = hexToBytes(i.deviceSkHex)
    const passed = i.passed.map((e: Any) => ({ epoch: e.epoch, secret: hexToBytes(e.secretHex), leftAt: e.leftAt }))
    expect(passed).toHaveLength(MAX_HISTORY_EPOCHS)
    const device = i.event.tags.find((t: string[]) => t[0] === 'p')[1]
    const options = { roomId: i.roomId, authoritySk, device, request: i.request, now: i.now, epoch: epochOf(i.epoch), removed: [] }
    const event = withStubbedRandomness(draws(i.randomHex), () => encodeEpochGrant({ ...options, passed }))
    expect(plain(event)).toEqual(i.event)

    const key = nip44.v2.utils.getConversationKey(deviceSk, i.authority)
    const body = nip44.v2.decrypt(i.event.content, key)
    expect(body).toBe(v.output.bodyJson)
    const wire = JSON.parse(body).passed
    expect(wire.map((e: Any) => Object.keys(e))).toEqual(wire.map(() => ['epoch', 'secret', 'left']))
    expect(wire.map((e: Any) => bytesToHex(base64urlnopad.decode(e.secret)))).toEqual(i.passed.map((e: Any) => e.secretHex))

    const read = (e: Event) => {
      const g = decodeEpochGrant(e, { roomId: i.roomId, authority: i.authority, deviceSk, request: i.request, now: i.now })
      if (!g || g.refused) return g
      const at = g.epoch as { epoch: number; secret: Uint8Array }
      return {
        epoch: at.epoch,
        secretHex: bytesToHex(at.secret),
        removed: g.removed,
        ...(g.passed ? { passed: g.passed.map((p) => ({ epoch: p.epoch, secretHex: bytesToHex(p.secret), leftAt: p.leftAt })) } : {}),
      }
    }
    expect(read(i.event)).toEqual(v.output.grant)
    expect(v.output.grant.passed).toEqual(i.passed)

    const extra = { epoch: 1, secret: new Uint8Array(32).fill(1), leftAt: i.now - 17 * 3600 }
    expect(() => encodeEpochGrant({ ...options, passed: [extra, ...passed] })).toThrow()
    expect(v.output.seventeen).toBe('refused')

    const conversation = nip44.v2.utils.getConversationKey(authoritySk, device)
    for (const [k, built] of Object.entries(i.malformed) as [string, Any][]) {
      expect(plain(rebuild(built, conversation, authoritySk))).toEqual(built.event)
      expect(nip44.v2.decrypt(built.event.content, key)).toBe(built.bodyJson)
      const got = read(built.event)
      expect(got).toEqual(v.output.malformed[k])
      expect(got).toEqual({ epoch: 18, secretHex: i.epoch.secretHex, removed: [] })
    }
    expect(JSON.parse(i.malformed.overCap.bodyJson).passed).toHaveLength(MAX_HISTORY_EPOCHS + 1)
  })

  it('epoch-grant-window-old-reader: 0.7.0 reads the current epoch and nothing else', () => {
    const v = vec('epoch-grant-window-old-reader')
    const i = v.input
    const deviceSk = hexToBytes(i.deviceSkHex)
    expect(i.event).toEqual(vec('epoch-grant-window').input.event)

    // 0.7.0's `decodeEpochGrant` body handling, line for line, with the
    // device key as the only key tried: it reads named fields and builds its
    // answer from them.
    const readAs070 = (event: Event) => {
      const body = JSON.parse(nip44.v2.decrypt(event.content, nip44.v2.utils.getConversationKey(deviceSk, event.pubkey)))
      if (body.v !== 1 || typeof body.request !== 'string' || body.request.toLowerCase() !== i.request) return null
      if (body.refused === 'removed' || body.refused === 'closed' || body.refused === 'unknown') return { refused: body.refused }
      if (!Number.isSafeInteger(body.epoch) || body.epoch < 0 || body.epoch > 1_000_000) return null
      const removed = Array.isArray(body.removed)
        ? [...new Set((body.removed as unknown[]).filter((p): p is string => typeof p === 'string' && /^[0-9a-f]{64}$/i.test(p)).map((p) => p.toLowerCase()))].sort()
        : []
      if (body.epoch === 0) return { epoch: 0, removed }
      if (typeof body.secret !== 'string') return null
      const secret = base64urlnopad.decode(body.secret)
      if (secret.length !== 32) return null
      return { epoch: body.epoch, secretHex: bytesToHex(secret), removed }
    }
    expect(readAs070(i.event)).toEqual(v.output.oldReader)

    // And it is exactly the new reader's answer without `passed`.
    const g = decodeEpochGrant(i.event, { roomId: i.roomId, authority: i.authority, deviceSk, request: i.request, now: i.now })
    expect(g && !g.refused).toBe(true)
    const { passed, epoch, ...rest } = g as Any
    expect(passed).toHaveLength(MAX_HISTORY_EPOCHS)
    expect({ epoch: epoch.epoch, secretHex: bytesToHex(epoch.secret), ...rest }).toEqual(v.output.oldReader)
  })

  it('history-window: every case keeps what the vector says', () => {
    const v = vec('history-window')
    expect(v.input.windowSeconds).toBe(HISTORY_WINDOW_SECONDS)
    expect(v.input.maxEpochs).toBe(MAX_HISTORY_EPOCHS)
    expect(v.input.cases.map((c: Any) => c.name)).toEqual(v.output.cases.map((c: Any) => c.name))
    v.input.cases.forEach((c: Any, n: number) => {
      expect(epochsInWindow(c.left, c.now)).toEqual(v.output.cases[n].kept)
    })
    const kept = (name: string) => v.output.cases.find((c: Any) => c.name === name).kept.map((e: Any) => e.epoch)
    expect(kept('edge')).toEqual([3, 2])
    expect(kept('cap')).toHaveLength(MAX_HISTORY_EPOCHS)
    expect(kept('weekly')).toEqual([10, 9, 8, 7])
    expect(kept('unsorted-and-doubled')).toEqual([5, 4, 2])
  })
})
