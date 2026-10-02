// Recomputes vectors/member-epoch-vectors.json (see
// scripts/generate-member-epoch.mjs and docs/member-epoch-catch-up.md)
// against `src/` directly: every event is rebuilt by the REAL encoder with
// its recorded random draws and must come out byte-identical, and every
// grant is fed through the REAL decoder and must give the recorded result.
// The commitment and the request key are also recomputed a second way, with
// @noble/hashes directly, so a bug shared by the generator and `src/` cannot
// round-trip undetected.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { hkdf } from '@noble/hashes/hkdf'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { schnorr } from '@noble/curves/secp256k1.js'
import { nip44 } from 'nostr-tools'
import { getPublicKey, type Event } from 'nostr-tools/pure'
import { withStubbedRandomness } from './lib/determinism.mjs'
import { deriveEpoch, encodeRekeyEvent } from '../src/epoch.js'
import { epochCommitment } from '../src/epoch-commit.js'
import {
  deriveMemberEpochRequestKey,
  decodeMemberEpochGrant,
  decodeMemberEpochRequest,
  encodeMemberEpochGrant,
  encodeMemberEpochRequest,
  readRekeyEvidence,
} from '../src/member-epoch.js'

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, 'member-epoch-vectors.json'), 'utf8'))
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any
const vectors = doc.groups.memberEpoch as Any[]
const vec = (name: string): Any => {
  const v = vectors.find((x) => x.name === name)
  if (!v) throw new Error(`no vector ${name}`)
  return v
}
const draws = (randomHex: string[]) => randomHex.map(hexToBytes)

describe('member-epoch-vectors', () => {
  it('is in the KithMoot vector format', () => {
    expect(doc.protocolVersion).toBe('kithmoot/v1')
    for (const v of vectors) {
      expect(typeof v.name).toBe('string')
      expect(['positive', 'negative']).toContain(v.kind)
      expect(typeof v.note).toBe('string')
    }
  })

  it('epoch-commitment, two ways', () => {
    const v = vec('epoch-commitment')
    const secret = hexToBytes(v.input.secretHex)
    expect(epochCommitment(v.input.roomId, v.input.epoch, secret)).toBe(v.output.commitHex)
    const independent = bytesToHex(hmac(sha256, secret, new TextEncoder().encode(`kithmoot/v1/epoch-commit:${v.input.roomId}:${v.input.epoch}`)))
    expect(independent).toBe(v.output.commitHex)
  })

  it('member-request-key, two ways', () => {
    const v = vec('member-request-key')
    const roomKey = hexToBytes(v.input.roomKeyHex)
    expect(bytesToHex(deriveMemberEpochRequestKey(roomKey))).toBe(v.output.keyHex)
    expect(bytesToHex(hkdf(sha256, roomKey, undefined, 'kithmoot/v1/member-epoch-request-key', 32))).toBe(v.output.keyHex)
  })

  for (const name of ['rekey-with-commitment', 'rekey-without-commitment']) {
    it(`${name}: the real encoder reproduces the event, and it reads as the recorded evidence`, () => {
      const v = vec(name)
      const i = v.input
      const previous = { epoch: i.previousEpoch, id: '', key: hexToBytes(i.previousKeyHex) }
      const event = withStubbedRandomness(draws(i.randomHex), () =>
        encodeRekeyEvent({
          roomId: i.roomId,
          authoritySk: hexToBytes(i.authoritySkHex),
          current: previous,
          next: { epoch: i.next.epoch, secret: hexToBytes(i.next.secretHex) },
          recipients: i.recipients,
          removed: i.removed,
          ...(name === 'rekey-with-commitment' ? { commit: true } : {}),
          now: i.createdAt,
        }),
      )
      expect(JSON.parse(JSON.stringify(event))).toEqual(i.event)
      expect(readRekeyEvidence(i.event as Event, { roomId: i.roomId, authority: i.authority, previous })).toEqual(v.output.evidence)
      const body = JSON.parse(nip44.v2.decrypt(i.event.content, previous.key))
      expect(Object.keys(body)).toEqual(name === 'rekey-with-commitment' ? ['v', 'epoch', 'removed', 'commit', 'keys'] : ['v', 'epoch', 'removed', 'keys'])
      if (name === 'rekey-with-commitment') {
        expect(i.previousKeyHex).toBe(bytesToHex(deriveEpoch({ epoch: 1, secret: hexToBytes(i.previousSecretHex) }).key))
      }
    })
  }

  it('member-request: the real encoder reproduces it, and a member decodes it', () => {
    const v = vec('member-request')
    const i = v.input
    const event = withStubbedRandomness(draws(i.randomHex), () =>
      encodeMemberEpochRequest({
        roomId: i.roomId,
        authority: i.authority,
        deviceSk: hexToBytes(i.requesterDeviceSkHex),
        roomKey: hexToBytes(i.roomKeyHex),
        credential: i.credential,
        have: i.have,
        now: i.now,
      }),
    )
    expect(JSON.parse(JSON.stringify(event))).toEqual(i.event)
    expect(decodeMemberEpochRequest(i.event, { roomId: i.roomId, authority: i.authority, roomKey: hexToBytes(i.roomKeyHex), now: i.now })).toEqual(v.output.decoded)
  })

  const request = vec('member-request').input.event
  const roomId = vec('member-request').input.roomId
  const memberDevice = vec('rekey-with-commitment').input.recipients[0]

  for (const v of vectors.filter((x) => x.name.startsWith('member-grant-'))) {
    it(`${v.name}: the real encoder rebuilds it byte for byte, and the real decoder gives the recorded result`, () => {
      const i = v.input
      // Signed by the recorded one-time key - the first, 48-byte draw, made a
      // key exactly as generateSecretKey does - and never by a member device.
      expect(i.grant.randomHex[0]).toHaveLength(96)
      expect(bytesToHex(schnorr.utils.randomSecretKey(hexToBytes(i.grant.randomHex[0])))).toBe(i.grant.signerSkHex)
      expect(i.grant.event.pubkey).toBe(getPublicKey(hexToBytes(i.grant.signerSkHex)))
      expect(i.grant.event.pubkey).not.toBe(memberDevice)
      expect(i.requests).toEqual([request.id])
      const rebuilt = withStubbedRandomness(draws(i.grant.randomHex), () =>
        encodeMemberEpochGrant({
          roomId: i.roomId,
          device: request.pubkey,
          request: request.id,
          epochs: i.grant.epochs.map((e: Any) => ({ epoch: e.epoch, secret: hexToBytes(e.secretHex) })),
          rekeys: i.rekeys.map((r: Any) => r.event),
          now: i.now,
        }),
      )
      expect(JSON.parse(JSON.stringify(rebuilt))).toEqual(i.grant.event)
      const decoded = decodeMemberEpochGrant(i.grant.event, {
        roomId: i.roomId,
        authority: i.authority,
        deviceSk: hexToBytes(i.requesterDeviceSkHex),
        requests: new Set(i.requests),
        current: { epoch: i.current.epoch, id: '', key: hexToBytes(i.current.keyHex) },
        participant: i.participant,
        removed: i.removed,
        ...(i.expected !== undefined ? { expected: i.expected } : {}),
        now: i.now,
      })
      const result = decoded && { epoch: decoded.epoch.epoch, secretHex: bytesToHex(decoded.epoch.secret), removed: decoded.removed }
      expect(result).toEqual(v.output.result)
      expect(v.kind === 'positive').toBe(result !== null)
    })
  }

  it('the epoch-0 key every grant starts from is the room key of the epoch-0 rekey', () => {
    const grantVec = vec('member-grant-accepted')
    expect(grantVec.input.current.keyHex).toBe(vec('rekey-without-commitment').input.previousKeyHex)
    expect(grantVec.input.roomId).toBe(roomId)
  })
})
