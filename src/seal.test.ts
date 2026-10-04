import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { SimRelay, SimTransport } from '../test/sim-relay.js'
import { createDeviceCredential } from './credential.js'
import { localIdentity } from './identity.js'
import { deriveRoom } from './room.js'
import { KINDS } from './kinds.js'
import {
  decodeEpochGrant,
  decodeRekeyEvent,
  deriveEpoch,
  encodeEpochGrant,
  encodeEpochRequest,
  encodeRekeyEvent,
  generateEpochSecret,
  hostRoomEpoch,
  requestRoomEpoch,
  sealCredential,
  type RoomEpoch,
} from './epoch.js'
import { decodeMemberEpochGrant, encodeMemberEpochGrant, hostMemberEpochDesk, requestMemberEpoch } from './member-epoch.js'
import { credentialSeal, generateSealKey, isSealPubkey, newerCredential, openSealed, sealTarget } from './seal.js'
import type { DeviceCredential } from './types.js'

const NOW = 1_800_000_000
const now = () => NOW
const ROOM_SECRET = new Uint8Array(32).fill(7)
const { roomId, roomKey } = deriveRoom(ROOM_SECRET)
const E0: RoomEpoch = { epoch: 0, secret: ROOM_SECRET }

const authoritySk = generateSecretKey()
const authority = getPublicKey(authoritySk)
const person = localIdentity(generateSecretKey())
const deviceSk = generateSecretKey()
const device = getPublicKey(deviceSk)

/** A point that is not on the curve: x = 5 has no square root. */
const OFF_CURVE = '0'.repeat(63) + '5'

function credential(opts: { seal?: string; expiresAt?: number; createdAt?: number; dev?: string; id?: ReturnType<typeof localIdentity> } = {}) {
  const at = opts.createdAt ?? NOW
  return createDeviceCredential({
    identity: opts.id ?? person,
    devicePubkey: opts.dev ?? device,
    roomId,
    expiresAt: opts.expiresAt ?? NOW + 3600,
    ...(opts.seal !== undefined ? { seal: opts.seal } : {}),
    now: () => at,
  })
}

/** A credential signed with whatever tags a test wants, as only a buggy
 *  minter could make. */
function credentialWithTags(tags: string[][]): DeviceCredential {
  return finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags, content: '' }, generateSecretKey()) as DeviceCredential
}

describe('the seal key in a credential', () => {
  it('rides last, under the participant signature, and its absence changes nothing', async () => {
    const seal = generateSealKey()
    const plain = await credential()
    const sealed = await credential({ seal: seal.pubkey })
    expect(sealed.tags.slice(0, -1)).toEqual(plain.tags)
    expect(sealed.tags.at(-1)).toEqual(['seal', seal.pubkey])
    expect(plain.tags.some((t) => t[0] === 'seal')).toBe(false)
    expect(credentialSeal(sealed)).toBe(seal.pubkey)
    expect(credentialSeal(plain)).toBeUndefined()
  })

  it('is refused at mint unless it is a point on the curve', async () => {
    await expect(credential({ seal: 'zz' })).rejects.toThrow(/seal key/)
    await expect(credential({ seal: OFF_CURVE })).rejects.toThrow(/seal key/)
    await expect(credential({ seal: generateSealKey().pubkey.toUpperCase() })).resolves.toBeDefined()
  })

  it('reads as unusable when doubled, malformed or off the curve', () => {
    const good = generateSealKey().pubkey
    const base = [['d', roomId], ['device', device], ['expiration', String(NOW + 60)]]
    expect(credentialSeal(credentialWithTags([...base, ['seal', good], ['seal', good]]))).toBeNull()
    expect(credentialSeal(credentialWithTags([...base, ['seal', 'abc']]))).toBeNull()
    expect(credentialSeal(credentialWithTags([...base, ['seal']]))).toBeNull()
    expect(credentialSeal(credentialWithTags([...base, ['seal', OFF_CURVE]]))).toBeNull()
    expect(isSealPubkey(OFF_CURVE)).toBe(false)
    expect(isSealPubkey(good)).toBe(true)
  })
})

describe('sealTarget', () => {
  it('is the seal key of a credential for this device, and the device key otherwise', async () => {
    const seal = generateSealKey()
    expect(sealTarget(device)).toBe(device)
    expect(sealTarget(device, await credential())).toBe(device)
    expect(sealTarget(device, await credential({ seal: seal.pubkey }))).toBe(seal.pubkey)
    expect(sealTarget(device.toUpperCase(), await credential({ seal: seal.pubkey }))).toBe(seal.pubkey)
    // Another device's credential says nothing about this one.
    const other = getPublicKey(generateSecretKey())
    expect(sealTarget(other, await credential({ seal: seal.pubkey }))).toBe(other)
    const base = [['d', roomId], ['device', device], ['expiration', String(NOW + 60)]]
    expect(sealTarget(device, credentialWithTags([...base, ['seal', OFF_CURVE]]))).toBe(device)
  })

  it('stays on the seal key after the credential lapses, never back to the device key', async () => {
    const seal = generateSealKey()
    const lapsed = await credential({ seal: seal.pubkey, createdAt: NOW - 7200, expiresAt: NOW - 3600 })
    expect(sealTarget(device, lapsed)).toBe(seal.pubkey)
  })
})

describe('newerCredential', () => {
  it('orders by expiry, then by created_at, and keeps the first on a tie', async () => {
    const early = await credential({ expiresAt: NOW + 100 })
    const late = await credential({ expiresAt: NOW + 200, createdAt: NOW - 50 })
    expect(newerCredential(early, late)).toBe(late)
    expect(newerCredential(late, early)).toBe(late)
    const restamped = await credential({ expiresAt: NOW + 100, createdAt: NOW + 10 })
    expect(newerCredential(early, restamped)).toBe(restamped)
    const twin = await credential({ expiresAt: NOW + 100 })
    expect(newerCredential(early, twin)).toBe(early)
  })
})

describe('openSealed', () => {
  it('tries each seal key, then the device key, and throws when none opens it', async () => {
    const seal = generateSealKey()
    const stale = generateSealKey()
    const toSeal = encodeEpochGrant({ roomId, authoritySk, device, request: 'ab'.repeat(32), now: NOW, refused: 'closed', credential: await credential({ seal: seal.pubkey }) })
    expect(() => openSealed(toSeal.content, authority, deviceSk, [stale.secretKey, seal.secretKey])).not.toThrow()
    expect(() => openSealed(toSeal.content, authority, deviceSk, [stale.secretKey])).toThrow()
    const toDevice = encodeEpochGrant({ roomId, authoritySk, device, request: 'ab'.repeat(32), now: NOW, refused: 'closed' })
    expect(() => openSealed(toDevice.content, authority, deviceSk, [seal.secretKey])).not.toThrow()
  })
})

describe('a rekey sealed to seal keys', () => {
  it('opens under the seal key, not under the device key alone; a bare recipient opens as before', async () => {
    const seal = generateSealKey()
    const bareSk = generateSecretKey()
    const next = { epoch: 1, secret: generateEpochSecret() }
    const rekey = encodeRekeyEvent({
      roomId,
      authoritySk,
      current: deriveEpoch(E0),
      next,
      recipients: [{ device, credential: await credential({ seal: seal.pubkey }) }, getPublicKey(bareSk)],
      removed: [],
      now: NOW,
    })
    const read = (sk: Uint8Array, sealSks?: Uint8Array[]) =>
      decodeRekeyEvent(rekey, { roomId, authority, current: deriveEpoch(E0), deviceSk: sk, ...(sealSks ? { sealSks } : {}) })
    expect(read(deviceSk, [seal.secretKey])?.secret).toEqual(next.secret)
    // The thief: the device key, and no seal key minted after the theft.
    const thief = read(deviceSk, [generateSealKey().secretKey])
    expect(thief).not.toBeNull()
    expect(thief?.secret).toBeUndefined()
    expect(read(bareSk)?.secret).toEqual(next.secret)
  })

  it('a recipient whose credential names no seal key is sealed to the device key, byte for byte as before', async () => {
    const next = { epoch: 1, secret: generateEpochSecret() }
    const asString = encodeRekeyEvent({ roomId, authoritySk, current: deriveEpoch(E0), next, recipients: [device], removed: [], now: NOW })
    const asRecipient = encodeRekeyEvent({ roomId, authoritySk, current: deriveEpoch(E0), next, recipients: [{ device, credential: await credential() }], removed: [], now: NOW })
    for (const event of [asString, asRecipient]) {
      expect(decodeRekeyEvent(event, { roomId, authority, current: deriveEpoch(E0), deviceSk })?.secret).toEqual(next.secret)
    }
  })
})

describe('grants sealed to seal keys', () => {
  it('the authority grant (20469) opens under the seal key only', async () => {
    const seal = generateSealKey()
    const epoch = { epoch: 3, secret: generateEpochSecret() }
    const request = encodeEpochRequest({ roomId, authority, deviceSk, roomKey, credential: await credential({ seal: seal.pubkey }), now: NOW })
    const grant = encodeEpochGrant({ roomId, authoritySk, device, request: request.id, now: NOW, epoch, credential: await credential({ seal: seal.pubkey }) })
    const opts = { roomId, authority, deviceSk, request: request.id, now: NOW }
    expect(decodeEpochGrant(grant, { ...opts, sealSks: [seal.secretKey] })).toEqual({ epoch, removed: [] })
    expect(decodeEpochGrant(grant, opts)).toBeNull()
  })

  it('the member grant (20472) opens under the seal key only', async () => {
    const seal = generateSealKey()
    const next = { epoch: 1, secret: generateEpochSecret() }
    const rekey = encodeRekeyEvent({ roomId, authoritySk, current: deriveEpoch(E0), next, recipients: [], removed: [], commit: true, now: NOW - 10 })
    const request = 'cd'.repeat(32)
    const grant = encodeMemberEpochGrant({ roomId, device, request, epochs: [next], rekeys: [rekey], credential: await credential({ seal: seal.pubkey }), now: NOW })
    const opts = { roomId, authority, deviceSk, requests: new Set([request]), current: deriveEpoch(E0), participant: person.pubkey, now: NOW }
    expect(decodeMemberEpochGrant(grant, { ...opts, sealSks: [seal.secretKey] })?.epoch).toEqual(next)
    expect(decodeMemberEpochGrant(grant, opts)).toBeNull()
  })
})

describe('sealCredential: what a desk seals its answer to', () => {
  it('the newer of the presented and the known credential, when the known one checks out', async () => {
    const oldSeal = generateSealKey()
    const newSeal = generateSealKey()
    const presented = await credential({ seal: oldSeal.pubkey, expiresAt: NOW + 1000 })
    const known = await credential({ seal: newSeal.pubkey, expiresAt: NOW + 2000 })
    const request = { device, participant: person.pubkey }
    expect(sealCredential(request, presented, undefined, roomId, NOW)).toBe(presented)
    expect(sealCredential(request, presented, () => known, roomId, NOW)).toBe(known)
    // Older known: the presented one stands.
    expect(sealCredential(request, known, () => presented, roomId, NOW)).toBe(known)
    // A known credential for another participant, another room, or a lapsed one is ignored.
    const stranger = await credential({ seal: newSeal.pubkey, expiresAt: NOW + 2000, id: localIdentity(generateSecretKey()) })
    expect(sealCredential(request, presented, () => stranger, roomId, NOW)).toBe(presented)
    expect(sealCredential(request, presented, () => known, deriveRoom(new Uint8Array(32).fill(1)).roomId, NOW)).toBe(presented)
    expect(sealCredential(request, presented, () => known, roomId, NOW + 2000)).toBe(presented)
    // A callback that throws is no answer.
    expect(sealCredential(request, presented, () => { throw new Error('boom') }, roomId, NOW)).toBe(presented)
  })
})

describe('healing at the desks', () => {
  /** The incident: the thief copied the device key and the seal key of the
   *  credential live then. The device has since renewed under a new seal
   *  key the room has seen, and the thief replays the old credential. */
  async function incident() {
    const copiedSeal = generateSealKey()
    const freshSeal = generateSealKey()
    const copied = await credential({ seal: copiedSeal.pubkey, createdAt: NOW - 1800, expiresAt: NOW + 1800 })
    const renewed = await credential({ seal: freshSeal.pubkey, expiresAt: NOW + 3600 })
    return { copiedSeal, freshSeal, copied, renewed }
  }

  it('the authority desk answers a replayed credential under the newer seal key', async () => {
    const { copiedSeal, freshSeal, copied, renewed } = await incident()
    const relay = new SimRelay()
    const epoch = { epoch: 2, secret: generateEpochSecret() }
    const desk = hostRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authoritySk,
      roomKey,
      current: () => epoch,
      removed: () => new Set(),
      credentialFor: (d) => (d === device ? renewed : undefined),
      now,
    })
    const ask = (sealSks: Uint8Array[], timeoutMs: number) =>
      requestRoomEpoch({ transport: new SimTransport(relay), roomId, authority, deviceSk, roomKey, credential: copied, sealSks: () => sealSks, now, timeoutMs, retryMs: 50 })
    await expect(ask([copiedSeal.secretKey], 300)).rejects.toThrow(/not answering/)
    expect((await ask([freshSeal.secretKey, copiedSeal.secretKey], 1_000)).epoch).toEqual(epoch)
    desk.close()
  })

  it('the member desk does the same', async () => {
    const { copiedSeal, freshSeal, copied, renewed } = await incident()
    const relay = new SimRelay()
    const next = { epoch: 1, secret: generateEpochSecret() }
    const rekey = encodeRekeyEvent({ roomId, authoritySk, current: deriveEpoch(E0), next, recipients: [], removed: [], commit: true, now: NOW - 10 })
    relay.publish(rekey)
    const desk = hostMemberEpochDesk({
      transport: new SimTransport(relay),
      roomId,
      authority,
      deviceSk: generateSecretKey(),
      roomKey,
      current: () => next,
      rekeyAt: (n) => (n === 1 ? rekey : undefined),
      removed: () => new Set(),
      credentialFor: (d) => (d === device ? renewed : undefined),
      jitterMs: 0,
      now,
    })
    const ask = (sealSks: Uint8Array[], timeoutMs: number) =>
      requestMemberEpoch({ transport: new SimTransport(relay), roomId, authority, deviceSk, roomKey, credential: copied, current: deriveEpoch(E0), sealSks: () => sealSks, now, timeoutMs, retryMs: 50 })
    await expect(ask([copiedSeal.secretKey], 300)).rejects.toThrow(/no current member/)
    expect((await ask([freshSeal.secretKey], 1_000)).epoch).toEqual(next)
    desk.close()
  })

  it('a desk that knows no newer credential answers the one presented', async () => {
    const { copiedSeal, copied } = await incident()
    const relay = new SimRelay()
    const epoch = { epoch: 2, secret: generateEpochSecret() }
    const desk = hostRoomEpoch({ transport: new SimTransport(relay), roomId, authoritySk, roomKey, current: () => epoch, removed: () => new Set(), now })
    const grant = await requestRoomEpoch({
      transport: new SimTransport(relay), roomId, authority, deviceSk, roomKey, credential: copied, sealSks: () => [copiedSeal.secretKey], now, timeoutMs: 1_000,
    })
    expect(grant.epoch).toEqual(epoch)
    desk.close()
  })
})
