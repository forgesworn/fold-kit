// Adapted from KithMoot's vectors/verify.test.ts: only the circle-layer
// groups this kit owns (see EXTRACTION.md) - room derivation, channel
// derivation, join URL, device credential, kindred proof, access
// evaluation, room epoch and epoch request admission. The other groups
// (roster event, signal wrap,
// room descriptor, TURN credential, agent ownership, chat attachment,
// approval control, verification words, and the message layer) stay in
// KithMoot, whose modules did not move here.
//
// Loads `kithmoot-vectors.json` (a subset of KithMoot's own file, copied
// byte-identical group by group - see EXTRACTION.md) and checks each vector
// two ways for anything signed or encrypted:
//
//   1. Recomputing the bytes from the vector's own recorded inputs via the
//      same low-level helpers `generate.mjs` used in KithMoot, and asserting
//      they equal what is on disk.
//   2. Feeding the vector's frozen output through the REAL verify/decode
//      function in this kit's `src/` and asserting it produces the recorded
//      result.
//
// The purely deterministic groups (room derivation, channel derivation, join
// URL) get the strongest check: the real `src/` function is called directly
// on the vector's input and must reproduce the recorded output exactly.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { schnorr } from '@noble/curves/secp256k1.js'
import { nip44 } from 'nostr-tools'
import { getPublicKey, type Event } from 'nostr-tools/pure'

import { finalizeDeterministic, kindredCanonicalMessage, withStubbedRandomness } from './lib/determinism.mjs'
import * as fx from './lib/fixtures.mjs'

import { KINDS } from '../src/kinds.js'
import { deriveRoom, decodeJoinUrl, encodeJoinUrl } from '../src/room.js'
import { deriveChannel } from '../src/channel.js'
import { verifyDeviceCredential, createDeviceCredential } from '../src/credential.js'
import type { ParticipantIdentity } from '../src/identity.js'
import { evaluateAccess, issueKindredProof } from '../src/access.js'
import { deriveEpoch, peekRekeyEvent, decodeRekeyEvent, decodeEpochRequest, deriveEpochRequestKey, epochRequestAdmission, signAdmins, verifyAdmins, canonicalAdmins, encodeRekeyEvent, encodeEpochRequest } from '../src/epoch.js'
import type { RoomPolicy } from '../src/types.js'

interface Vector {
  name: string
  kind: 'positive' | 'negative'
  note: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  input: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  output: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  expected?: any
}

interface VectorDocument {
  protocolVersion: string
  generatedBy: string
  nostrToolsVersion: string
  groups: Record<string, Vector[]>
}

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, 'kithmoot-vectors.json'), 'utf8')) as VectorDocument
const { groups } = doc

function vec(group: string, name: string): Vector {
  const found = groups[group]?.find((v) => v.name === name)
  if (!found) throw new Error(`missing vector ${group}/${name}`)
  return found
}

describe('vector file shape', () => {
  it('carries the protocol version and nostr-tools pin this suite was written against', () => {
    expect(doc.protocolVersion).toBe('kithmoot/v1')
    expect(doc.nostrToolsVersion).toBe('2.25.0')
  })

  it('every group that has a verify/decode/throw path includes at least one negative case', () => {
    for (const group of ['deviceCredential', 'accessEvaluation', 'joinUrl', 'roomEpoch', 'epochRequestAdmission']) {
      const negatives = groups[group].filter((v) => v.kind === 'negative')
      expect(negatives.length, `${group} has no negative vectors`).toBeGreaterThan(0)
    }
  })
})

describe('room derivation', () => {
  for (const v of groups.roomDerivation) {
    it(v.name, () => {
      const { roomId, roomKey } = deriveRoom(hexToBytes(v.input.secretHex))
      expect(roomId).toBe(v.output.roomId)
      expect(bytesToHex(roomKey)).toBe(v.output.roomKeyHex)
    })
  }
})

describe('channel derivation', () => {
  for (const v of groups.channelDerivation) {
    it(v.name, () => {
      const { id, key } = deriveChannel(v.input.roomId, hexToBytes(v.input.roomKeyHex), v.input.channel)
      expect(id).toBe(v.output.id)
      expect(bytesToHex(key)).toBe(v.output.keyHex)
      if (v.input.channel === undefined) {
        expect(id).toBe(v.input.roomId)
        expect(bytesToHex(key)).toBe(v.input.roomKeyHex)
      } else {
        expect(id).not.toBe(v.input.roomId)
        expect(bytesToHex(key)).not.toBe(v.input.roomKeyHex)
      }
    })
  }
})

describe('join URL', () => {
  for (const v of groups.joinUrl) {
    it(v.name, () => {
      if (v.kind === 'negative') {
        expect(() => decodeJoinUrl(v.input.url)).toThrow(v.output.error)
        return
      }
      const policy = (v.input.policy ?? undefined) as RoomPolicy | undefined
      const url = encodeJoinUrl(v.input.base, hexToBytes(v.input.secretHex), v.input.relays, policy)
      expect(url).toBe(v.output.url)

      const decoded = decodeJoinUrl(url)
      expect(bytesToHex(decoded.secret)).toBe(v.output.decoded.secretHex)
      expect(decoded.relays).toEqual(v.output.decoded.relays)
      expect(decoded.policy ?? null).toEqual(v.output.decoded.policy)
    })
  }
})

/** Rebuilds a device credential exactly as `generate.mjs` did, from a
 *  vector's own recorded inputs. */
function rebuildCredential(v: Vector): Event {
  return finalizeDeterministic(
    {
      kind: KINDS.CREDENTIAL,
      created_at: v.input.createdAt,
      tags: [
        ['d', v.input.roomId],
        ['device', v.input.devicePubkey],
        ['expiration', String(v.input.expiresAt)],
      ],
      content: '',
    },
    hexToBytes(v.input.participantSkHex),
    hexToBytes(v.input.auxRandHex),
  ) as Event
}

describe('device credential', () => {
  it('valid: reproduces the exact event, and the real implementation accepts it', () => {
    const v = vec('deviceCredential', 'valid')
    expect(rebuildCredential(v)).toEqual(v.output.event)

    const result = verifyDeviceCredential(v.output.event as Event, v.expected.verify)
    expect(result).toEqual(v.expected.result)
    expect(result).toEqual({ ok: true, participant: fx.PARTICIPANT_A, device: fx.DEVICE_A })
  })

  it('wrong-room: the real implementation rejects it', () => {
    const v = vec('deviceCredential', 'wrong-room')
    const result = verifyDeviceCredential(v.input.event as Event, v.input.verify)
    expect(result).toEqual(v.output.result)
    expect(result).toEqual({ ok: false, reason: 'wrong room' })
  })

  it('expired: reproduces the exact event, and the real implementation rejects it', () => {
    const v = vec('deviceCredential', 'expired')
    const event = rebuildCredential(v)
    expect(event).toEqual(v.output.event)
    expect(verifyDeviceCredential(event, v.input.verify)).toEqual(v.output.result)
    expect(v.output.result).toEqual({ ok: false, reason: 'expired' })
  })

  it('tampered-signature: the real implementation rejects it', () => {
    const v = vec('deviceCredential', 'tampered-signature')
    const result = verifyDeviceCredential(v.input.event as Event, v.input.verify)
    expect(result).toEqual(v.output.result)
    expect(result).toEqual({ ok: false, reason: 'bad signature' })
  })

  it('valid: the REAL createDeviceCredential (not just a hand rebuild) reproduces the exact event', async () => {
    const v = vec('deviceCredential', 'valid')
    const sk = hexToBytes(v.input.participantSkHex as string)
    const identity: ParticipantIdentity = {
      pubkey: getPublicKey(sk),
      async signEvent(unsigned) {
        return finalizeDeterministic(unsigned, sk, hexToBytes(v.input.auxRandHex as string)) as Event
      },
    }
    const cred = await createDeviceCredential({
      identity,
      devicePubkey: v.input.devicePubkey as string,
      roomId: v.input.roomId as string,
      expiresAt: v.input.expiresAt as number,
      now: () => v.input.createdAt as number,
    })
    expect(JSON.parse(JSON.stringify(cred))).toEqual(v.output.event)
    const result = verifyDeviceCredential(cred, v.expected!.verify)
    expect(result).toEqual(v.expected!.result)
  })
})

describe('kindred proof', () => {
  for (const tier of ['ken', 'kith', 'kin']) {
    it(`${tier}: reproduces the exact proof and its signature verifies`, () => {
      const v = vec('kindredProof', tier)
      const message = kindredCanonicalMessage(
        v.input.tier,
        v.input.participant,
        v.input.roomId,
        v.input.nonce,
        v.input.expiresAt,
      )
      const hostSk = hexToBytes(v.input.hostSkHex)
      const sig = schnorr.sign(message, hostSk, hexToBytes(v.input.auxRandHex))
      const proof = {
        tier: v.input.tier,
        participant: v.input.participant,
        issuer: getPublicKey(hostSk),
        room: v.input.roomId,
        nonce: v.input.nonce,
        sig: bytesToHex(sig),
        expiresAt: v.input.expiresAt,
      }
      expect(proof).toEqual(v.output.proof)
      expect(schnorr.verify(sig, message, hexToBytes(proof.issuer))).toBe(true)

      expect(
        issueKindredProof({
          hostSk,
          participant: v.input.participant,
          tier: v.input.tier,
          roomId: v.input.roomId,
          nonce: v.input.nonce,
          expiresAt: v.input.expiresAt,
        }),
      ).toMatchObject({
        tier: proof.tier,
        participant: proof.participant,
        issuer: proof.issuer,
        room: proof.room,
        nonce: proof.nonce,
        expiresAt: proof.expiresAt,
      })
    })
  }
})

describe('access evaluation', () => {
  for (const v of groups.accessEvaluation) {
    it(`${v.name}: matches the frozen vector`, () => {
      const result = evaluateAccess(
        v.input.policy,
        v.input.participant,
        v.input.proof ?? undefined,
        v.input.now,
        v.input.roomId,
      )
      expect(result).toEqual(v.output.result)
    })
  }
})

describe('epoch request admission', () => {
  const proof = groups.epochRequestAdmission.find((x) => x.name === 'admission-proof')!
  it(proof.name, () => {
    const roomKey = hexToBytes(proof.input.roomKeyHex as string)
    expect(bytesToHex(deriveEpochRequestKey(roomKey))).toBe(proof.output.requestKeyHex)
    expect(
      epochRequestAdmission({
        roomKey,
        roomId: proof.input.roomId as string,
        authority: proof.input.authority as string,
        device: proof.input.device as string,
        createdAt: proof.input.createdAt as number,
      }),
    ).toBe(proof.output.admission)
    expect(proof.input.message).toBe(
      `kithmoot/v1/epoch-request:${proof.input.roomId}:${proof.input.authority}:${proof.input.device}:${proof.input.createdAt}`,
    )
  })

  it('request: the REAL encodeEpochRequest (not just a hand rebuild) reproduces the exact event', () => {
    const v = vec('epochRequestAdmission', 'request')
    const authority = getPublicKey(hexToBytes(v.expected!.decode.authoritySkHex as string))
    const event = withStubbedRandomness(
      [hexToBytes(v.input.nonceHex as string), hexToBytes(v.input.auxRandHex as string)],
      () =>
        encodeEpochRequest({
          roomId: v.expected!.decode.roomId as string,
          authority,
          deviceSk: hexToBytes(v.input.deviceSkHex as string),
          roomKey: hexToBytes(v.expected!.decode.roomKeyHex as string),
          credential: (v.input.body as { credential: unknown }).credential as never,
          now: (v.input.event as Event).created_at,
        }),
    )
    expect(JSON.parse(JSON.stringify(event))).toEqual(v.input.event)
  })

  it('request: the REAL encodeEpochRequest actually carries a kindred proof when one is given (M17, no committed vector carries one)', () => {
    const roomId = deriveRoom(fx.ROOM_SECRET_1).roomId
    const authority = fx.AUTHORITY
    const proof = { tier: 'kith', participant: fx.PARTICIPANT_A, issuer: fx.HOST, room: roomId, nonce: 'ab'.repeat(32), sig: 'cd'.repeat(64) } as const
    const credential = { kind: KINDS.CREDENTIAL, created_at: fx.CREDENTIAL_CREATED_AT, tags: [['d', roomId], ['device', fx.KEPT_DEVICE], ['expiration', String(fx.CREDENTIAL_EXPIRES_AT)]], content: '', pubkey: fx.PARTICIPANT_A, id: '00'.repeat(32), sig: '00'.repeat(64) }
    const event = encodeEpochRequest({
      roomId, authority, deviceSk: fx.KEPT_DEVICE_SK, roomKey: deriveRoom(fx.ROOM_SECRET_1).roomKey,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      credential: credential as any, proof: proof as any, now: fx.EPOCH_CREATED_AT,
    })
    const conversationKey = nip44.v2.utils.getConversationKey(fx.KEPT_DEVICE_SK, authority)
    const body = JSON.parse(nip44.v2.decrypt(event.content, conversationKey)) as { proof?: { nonce: string } }
    expect(body.proof).toBeDefined()
    expect(body.proof!.nonce).toBe(proof.nonce)
  })

  for (const v of groups.epochRequestAdmission.filter((x) => x.name.startsWith('request'))) {
    it(v.name, () => {
      const decode = v.expected!.decode as Record<string, unknown>
      const result = decodeEpochRequest(v.input.event as Event, {
        roomId: decode.roomId as string,
        authoritySk: hexToBytes(decode.authoritySkHex as string),
        roomKey: hexToBytes(decode.roomKeyHex as string),
        now: decode.now as number,
      })
      expect(result).toEqual(v.expected!.result)
      if (v.kind === 'negative') expect(result).toBeNull()
      else expect(result).not.toBeNull()
    })
  }
})

describe('room epoch', () => {
  for (const v of groups.roomEpoch.filter((x) => x.name.startsWith('epoch-'))) {
    it(v.name, () => {
      const keys = deriveEpoch({ epoch: v.input.epoch as number, secret: hexToBytes(v.input.secretHex as string) })
      expect(keys.epoch).toBe(v.output.epoch)
      expect(keys.id).toBe(v.output.id)
      expect(bytesToHex(keys.key)).toBe(v.output.keyHex)
      if (v.input.epoch === 0) {
        const room = deriveRoom(hexToBytes(v.input.secretHex as string))
        expect(keys.id).toBe(room.roomId)
        expect(bytesToHex(keys.key)).toBe(bytesToHex(room.roomKey))
      }
    })
  }

  function rekeyArgs(decode: Record<string, unknown>) {
    return {
      roomId: decode.roomId as string,
      authority: decode.authority as string,
      current: {
        epoch: (decode.current as Record<string, unknown>).epoch as number,
        id: (decode.current as Record<string, unknown>).id as string,
        key: hexToBytes((decode.current as Record<string, unknown>).keyHex as string),
      },
      deviceSk: hexToBytes(decode.deviceSkHex as string),
    }
  }

  function noticeJson(notice: ReturnType<typeof decodeRekeyEvent>) {
    if (notice === null) return null
    const { secret, ...rest } = notice
    return { ...rest, ...(secret ? { secretHex: bytesToHex(secret) } : {}) }
  }

  it('rekey: the kept device reads the notice and gets the successor secret', () => {
    const v = vec('roomEpoch', 'rekey')
    const args = rekeyArgs(v.expected!.decode as Record<string, unknown>)
    expect(peekRekeyEvent(v.input.event as Event, { roomId: args.roomId, authority: args.authority })).toBe(v.output.peek)
    const result = decodeRekeyEvent(v.input.event as Event, args)
    expect(noticeJson(result)).toEqual(v.expected!.result)
    expect(result!.epoch).toBe(1)
    expect(result!.removed).toEqual([fx.REMOVED_DEVICE])
    expect(result!.secret).toBeDefined()
    expect(deriveEpoch({ epoch: 1, secret: result!.secret! }).id).toBe(deriveEpoch({ epoch: 1, secret: fx.EPOCH_SECRET_1 }).id)
    expect(JSON.stringify(v.input.event)).not.toContain(bytesToHex(fx.EPOCH_SECRET_1))
  })

  it('rekey: the REAL encodeRekeyEvent (not just a hand rebuild) reproduces the exact event', () => {
    const v = vec('roomEpoch', 'rekey')
    const event = withStubbedRandomness(
      [hexToBytes(v.input.sealNonceHex as string), hexToBytes(v.input.nonceHex as string), hexToBytes(v.input.auxRandHex as string)],
      () =>
        encodeRekeyEvent({
          roomId: (v.input.event as Event).tags.find((t) => t[0] === 'd')![1]!,
          authoritySk: hexToBytes(v.input.authoritySkHex as string),
          current: { epoch: v.input.currentEpoch as number, id: deriveRoom(fx.ROOM_SECRET_1).roomId, key: hexToBytes(v.input.currentKeyHex as string) },
          next: { epoch: (v.input.next as { epoch: number }).epoch, secret: hexToBytes((v.input.next as { secretHex: string }).secretHex) },
          recipients: v.input.recipients as string[],
          removed: v.input.removed as string[],
          by: v.input.by as string,
          now: v.input.createdAt as number,
        }),
    )
    expect(JSON.parse(JSON.stringify(event))).toEqual(v.input.event)
  })

  it('rekey: the removed device reads the notice and gets no secret', () => {
    const v = vec('roomEpoch', 'rekey-read-by-the-removed-device')
    const result = decodeRekeyEvent(v.input.event as Event, rekeyArgs(v.expected!.decode as Record<string, unknown>))
    expect(noticeJson(result)).toEqual(v.expected!.result)
    expect(result!.secret).toBeUndefined()
    expect(result!.removed).toContain(fx.REMOVED_DEVICE)
  })

  it('rekey-closed: the epoch advances and nobody is given it', () => {
    const v = vec('roomEpoch', 'rekey-closed')
    const result = decodeRekeyEvent(v.input.event as Event, rekeyArgs(v.expected!.decode as Record<string, unknown>))
    expect(noticeJson(result)).toEqual(v.expected!.result)
    expect(result!.closed).toBe(true)
    expect(result!.secret).toBeUndefined()
  })

  it('rekey-closed: the REAL encodeRekeyEvent actually writes `closed: true` and seals no copies, round-tripped independently of any recorded vector', () => {
    const authoritySk = fx.PARTICIPANT_A_SK
    const authority = getPublicKey(authoritySk)
    const roomId = deriveRoom(fx.ROOM_SECRET_1).roomId
    const current = deriveEpoch({ epoch: 0, secret: fx.ROOM_SECRET_1 })
    const closedEvent = encodeRekeyEvent({
      roomId, authoritySk, current, next: { epoch: 1, secret: fx.EPOCH_SECRET_2 }, recipients: [], removed: [], closed: true, now: fx.REKEY_CREATED_AT,
    })
    const decoded = decodeRekeyEvent(closedEvent, { roomId, authority, current, deviceSk: fx.KEPT_DEVICE_SK })
    expect(decoded).not.toBeNull()
    expect(decoded!.closed).toBe(true)
    expect(decoded!.secret).toBeUndefined()

    const openEvent = encodeRekeyEvent({
      roomId, authoritySk, current, next: { epoch: 1, secret: fx.EPOCH_SECRET_2 }, recipients: [fx.KEPT_DEVICE], removed: [], closed: false, now: fx.REKEY_CREATED_AT,
    })
    const openDecoded = decodeRekeyEvent(openEvent, { roomId, authority, current, deviceSk: fx.KEPT_DEVICE_SK })
    expect(openDecoded!.closed).toBe(false)
    expect(openDecoded!.secret).toBeDefined()
  })

  for (const name of ['rekey-not-the-authority', 'rekey-skips-an-epoch']) {
    it(`${name}: refused`, () => {
      const v = vec('roomEpoch', name)
      const result = decodeRekeyEvent(v.input.event as Event, rekeyArgs(v.input.decode as Record<string, unknown>))
      expect(result).toBeNull()
      expect(result).toEqual(v.output.result ?? null)
    })
  }

  it('admins-signature: canonical, and bound to its epoch', () => {
    const v = vec('roomEpoch', 'admins-signature')
    const admins = v.input.admins as string[]
    const roomId = v.input.roomId as string
    const epoch = v.input.epoch as number
    expect(canonicalAdmins(admins)).toEqual(v.output.canonical)
    expect(verifyAdmins({ roomId, epoch, admins, sig: v.output.sig as string, authority: fx.AUTHORITY })).toBe(true)
    expect(
      verifyAdmins({ roomId, epoch, admins: [...admins].reverse(), sig: v.output.sig as string, authority: fx.AUTHORITY }),
    ).toBe(true)
    const mine = signAdmins({ roomId, epoch, admins, authoritySk: hexToBytes(v.input.authoritySkHex as string) })
    expect(verifyAdmins({ roomId, epoch, admins, sig: mine, authority: fx.AUTHORITY })).toBe(true)
  })

  it('admins-signature-another-epoch: refused', () => {
    const v = vec('roomEpoch', 'admins-signature-another-epoch')
    expect(
      verifyAdmins({
        roomId: v.input.roomId as string,
        epoch: v.input.epoch as number,
        admins: v.input.admins as string[],
        sig: v.input.sig as string,
        authority: v.input.authority as string,
      }),
    ).toBe(false)
  })
})
