// Recomputes vectors/seal-vectors.json (see scripts/generate-seal.mjs and
// docs/seal-key.md) against `src/` directly: every event is rebuilt by the
// REAL encoder with its recorded random draws and must come out
// byte-identical, and every reader is the REAL decoder. Where a copy is
// sealed to a seal key, it is also opened a second way, with nostr-tools'
// NIP-44 directly, so a bug shared by the generator and `src/` cannot
// round-trip undetected.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { schnorr } from '@noble/curves/secp256k1.js'
import { nip44 } from 'nostr-tools'
import { getPublicKey, type Event } from 'nostr-tools/pure'
import { withStubbedRandomness } from './lib/determinism.mjs'
import { verifyDeviceCredential } from '../src/credential.js'
import {
  decodeEpochGrant,
  decodeEpochRequest,
  decodeRekeyEvent,
  encodeEpochGrant,
  encodeEpochRequest,
  encodeRekeyEvent,
  sealCredential,
} from '../src/epoch.js'
import { decodeMemberEpochGrant, encodeMemberEpochGrant } from '../src/member-epoch.js'
import { credentialSeal, newerCredential, sealTarget } from '../src/seal.js'

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, 'seal-vectors.json'), 'utf8'))
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any
const vectors = doc.groups.seal as Any[]
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
const keys = (key: string) => ({ epoch: 0, id: '', key: hexToBytes(key) })
const sealOf = (c: Any) => {
  const s = credentialSeal(c)
  return s === undefined ? 'none' : s === null ? 'unusable' : s
}

describe('seal-vectors', () => {
  it('is in the KithMoot vector format', () => {
    expect(doc.protocolVersion).toBe('kithmoot/v1')
    for (const v of vectors) {
      expect(typeof v.name).toBe('string')
      expect(['positive', 'negative']).toContain(v.kind)
      expect(typeof v.note).toBe('string')
    }
  })

  it('credential-seal-key: the seal tag rides last, verifies, and names a point', () => {
    const v = vec('credential-seal-key')
    const c = v.input.credential
    expect(verifyDeviceCredential(c, { roomId: v.input.roomId, now: v.input.createdAt }).ok).toBe(true)
    expect(c.pubkey).toBe(getPublicKey(hexToBytes(v.input.participantSkHex)))
    expect(c.tags.at(-1)).toEqual(['seal', getPublicKey(hexToBytes(v.input.sealSkHex))])
    expect(() => schnorr.utils.lift_x(BigInt(`0x${v.output.seal}`))).not.toThrow()
    expect(sealOf(c)).toBe(v.output.seal)
    expect(sealTarget(v.input.device, c)).toBe(v.output.sealTarget)
  })

  it('credential-without-seal: the same tags without the last', () => {
    const v = vec('credential-without-seal')
    const sealed = vec('credential-seal-key').input.credential
    expect(v.input.credential.tags).toEqual(sealed.tags.slice(0, -1))
    expect(verifyDeviceCredential(v.input.credential, { roomId: v.input.roomId, now: v.input.createdAt }).ok).toBe(true)
    expect(sealOf(v.input.credential)).toBe('none')
    expect(sealTarget(v.input.device, v.input.credential)).toBe(v.output.sealTarget)
    expect(v.output.sealTarget).toBe(v.input.device)
  })

  for (const name of ['credential-seal-doubled', 'credential-seal-off-curve']) {
    it(`${name}: unusable, and sealed to the device key`, () => {
      const v = vec(name)
      const device = v.input.credential.tags.find((t: string[]) => t[0] === 'device')[1]
      expect(sealOf(v.input.credential)).toBe('unusable')
      expect(v.output.seal).toBe('unusable')
      expect(sealTarget(device, v.input.credential)).toBe(device)
      expect(v.output.sealTarget).toBe(device)
    })
  }

  it('newer-credential', () => {
    const v = vec('newer-credential')
    expect(newerCredential(v.input.a, v.input.b) === v.input.b ? 'b' : 'a').toBe(v.output.newer)
    expect(newerCredential(v.input.b, v.input.a) === v.input.b ? 'b' : 'a').toBe(v.output.newer)
  })

  it('rekey-seal: the real encoder reproduces it, and only the live seal key opens the sealed copy', () => {
    const v = vec('rekey-seal')
    const i = v.input
    const event = withStubbedRandomness(draws(i.randomHex), () =>
      encodeRekeyEvent({
        roomId: i.roomId,
        authoritySk: hexToBytes(i.authoritySkHex),
        current: keys(i.previousKeyHex),
        next: { epoch: i.next.epoch, secret: hexToBytes(i.next.secretHex) },
        recipients: i.recipients,
        removed: [],
        now: i.createdAt,
      }),
    )
    expect(plain(event)).toEqual(i.event)
    const read = (deviceSkHex: string, sealSkHexes: string[]) => {
      const n = decodeRekeyEvent(i.event as Event, {
        roomId: i.roomId,
        authority: i.authority,
        current: keys(i.previousKeyHex),
        deviceSk: hexToBytes(deviceSkHex),
        sealSks: sealSkHexes.map(hexToBytes),
      })
      return n && { epoch: n.epoch, ...(n.secret ? { secretHex: bytesToHex(n.secret) } : {}) }
    }
    expect(read(i.deviceSkHex, [i.renewedSealSkHex, i.copiedSealSkHex])).toEqual(v.output.renewedDevice)
    expect(read(i.deviceSkHex, [i.copiedSealSkHex])).toEqual(v.output.thief)
    expect(read(i.bareDeviceSkHex, [])).toEqual(v.output.bareDevice)
    expect(v.output.thief.secretHex).toBeUndefined()

    // A second way: open each copy with NIP-44 directly, under the key it names.
    const body = JSON.parse(nip44.v2.decrypt(i.event.content, hexToBytes(i.previousKeyHex)))
    const device = getPublicKey(hexToBytes(i.deviceSkHex))
    const bare = getPublicKey(hexToBytes(i.bareDeviceSkHex))
    expect(Object.keys(body.keys).sort()).toEqual([device, bare].sort())
    const open = (sk: string, copy: string) => JSON.parse(nip44.v2.decrypt(copy, nip44.v2.utils.getConversationKey(hexToBytes(sk), i.authority)))
    expect(open(i.renewedSealSkHex, body.keys[device]).secret).toBeDefined()
    expect(() => open(i.deviceSkHex, body.keys[device])).toThrow()
    expect(open(i.bareDeviceSkHex, body.keys[bare]).secret).toBeDefined()
    expect(v.output.sealedTo[device]).toBe(getPublicKey(hexToBytes(i.renewedSealSkHex)))
  })

  it('rekey-without-seal-keys: byte-identical to a rekey given bare devices', () => {
    const v = vec('rekey-without-seal-keys')
    const i = v.input
    const encode = (recipients: Any[]) =>
      withStubbedRandomness(draws(i.randomHex), () =>
        encodeRekeyEvent({
          roomId: i.roomId,
          authoritySk: hexToBytes(i.authoritySkHex),
          current: keys(i.previousKeyHex),
          next: { epoch: i.next.epoch, secret: hexToBytes(i.next.secretHex) },
          recipients,
          removed: [],
          now: i.createdAt,
        }),
      )
    expect(plain(encode(i.recipients))).toEqual(i.event)
    expect(plain(encode(i.recipients.map((r: Any) => (typeof r === 'string' ? r : r.device))))).toEqual(i.event)
    const n = decodeRekeyEvent(i.event as Event, { roomId: i.roomId, authority: i.authority, current: keys(i.previousKeyHex), deviceSk: hexToBytes(i.deviceSkHex) })
    expect(n && { epoch: n.epoch, secretHex: n.secret && bytesToHex(n.secret) }).toEqual(v.output.device)
  })

  it('epoch-grant-seal: the desk seals to the newer credential, and the thief cannot open it', () => {
    const v = vec('epoch-grant-seal')
    const i = v.input
    const deviceSk = hexToBytes(i.deviceSkHex)
    const authoritySk = hexToBytes(i.authoritySkHex)
    const roomKey = hexToBytes(i.roomKeyHex)
    const request = withStubbedRandomness(draws(i.request.randomHex), () =>
      encodeEpochRequest({ roomId: i.roomId, authority: i.authority, deviceSk, roomKey, credential: i.presented, now: i.now }),
    )
    expect(plain(request)).toEqual(i.request.event)
    const decoded = decodeEpochRequest(request, { roomId: i.roomId, authoritySk, roomKey, now: i.now })
    expect(decoded).not.toBeNull()
    const chosen = sealCredential(decoded!, i.presented, () => i.known, i.roomId, i.now)
    expect(chosen).toBe(i.known)
    expect(sealTarget(decoded!.device, chosen)).toBe(v.output.sealedTo)
    const grant = withStubbedRandomness(draws(i.grant.randomHex), () =>
      encodeEpochGrant({
        roomId: i.roomId,
        authoritySk,
        device: decoded!.device,
        request: request.id,
        now: i.now,
        epoch: { epoch: i.epoch.epoch, secret: hexToBytes(i.epoch.secretHex) },
        removed: [],
        credential: chosen,
      }),
    )
    expect(plain(grant)).toEqual(i.grant.event)
    const read = (sealSkHexes: string[]) => {
      const g = decodeEpochGrant(grant, { roomId: i.roomId, authority: i.authority, deviceSk, sealSks: sealSkHexes.map(hexToBytes), request: request.id, now: i.now })
      return g && 'epoch' in g && g.epoch.epoch > 0 ? { epoch: g.epoch.epoch, secretHex: bytesToHex((g.epoch as { secret: Uint8Array }).secret) } : g
    }
    expect(read([i.renewedSealSkHex, i.copiedSealSkHex])).toEqual(v.output.renewedDevice)
    expect(read([i.copiedSealSkHex])).toEqual(v.output.thief)
    expect(v.output.thief).toBeNull()
    expect(() => nip44.v2.decrypt(grant.content, nip44.v2.utils.getConversationKey(hexToBytes(i.renewedSealSkHex), i.authority))).not.toThrow()
  })

  it('member-grant-seal: the real encoder reproduces it, and the thief cannot open it', () => {
    const v = vec('member-grant-seal')
    const i = v.input
    const deviceSk = hexToBytes(i.deviceSkHex)
    const grant = withStubbedRandomness(draws(i.grant.randomHex), () =>
      encodeMemberEpochGrant({
        roomId: i.roomId,
        device: getPublicKey(deviceSk),
        request: i.request,
        epochs: [{ epoch: i.epoch.epoch, secret: hexToBytes(i.epoch.secretHex) }],
        rekeys: [i.rekey.event],
        credential: i.credential,
        now: i.now,
      }),
    )
    expect(plain(grant)).toEqual(i.grant.event)
    expect(grant.pubkey).toBe(getPublicKey(hexToBytes(i.grant.signerSkHex)))
    const read = (sealSkHexes: string[]) => {
      const g = decodeMemberEpochGrant(grant, {
        roomId: i.roomId,
        authority: i.authority,
        deviceSk,
        sealSks: sealSkHexes.map(hexToBytes),
        requests: new Set([i.request]),
        current: keys(i.currentKeyHex),
        participant: i.participant,
        now: i.now,
      })
      return g && { epoch: g.epoch.epoch, secretHex: bytesToHex(g.epoch.secret) }
    }
    expect(read([i.renewedSealSkHex, i.copiedSealSkHex])).toEqual(v.output.renewedDevice)
    expect(read([i.copiedSealSkHex])).toEqual(v.output.thief)
    expect(v.output.thief).toBeNull()
    expect(sealTarget(getPublicKey(deviceSk), i.credential)).toBe(v.output.sealedTo)
  })
})
