import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { SimRelay, SimTransport } from '../test/sim-relay.js'
import { createDeviceCredential } from './credential.js'
import { localIdentity } from './identity.js'
import { deriveRoom } from './room.js'
import { KINDS } from './kinds.js'
import {
  EpochRefusedError,
  decodeEpochGrant,
  decodeEpochRequest,
  decodeRekeyEvent,
  deriveEpoch,
  encodeEpochGrant,
  encodeEpochRequest,
  epochRequestAdmission,
  encodeRekeyEvent,
  generateEpochSecret,
  hostRoomEpoch,
  peekRekeyEvent,
  requestRoomEpoch,
  signAdmins,
  verifyAdmins,
  signChannels,
  verifyChannels,
  canonicalChannels,
  RESERVED_CHANNELS,
} from './epoch.js'

const NOW = 1_800_000_000
const now = () => NOW
const ROOM_SECRET = new Uint8Array(32).fill(7)
const { roomId, roomKey } = deriveRoom(ROOM_SECRET)

describe('deriveEpoch', () => {
  it('epoch 0 is the room, byte for byte', () => {
    const e0 = deriveEpoch({ epoch: 0, secret: ROOM_SECRET })
    expect(e0.id).toBe(roomId)
    expect(e0.key).toEqual(roomKey)
  })

  it('a later epoch has its own id and key, and neither is the room id', () => {
    const secret = new Uint8Array(32).fill(9)
    const e1 = deriveEpoch({ epoch: 1, secret })
    const e2 = deriveEpoch({ epoch: 2, secret })
    expect(e1.id).toMatch(/^[0-9a-f]{64}$/)
    expect(e1.id).not.toBe(roomId)
    expect(e1.key).not.toEqual(roomKey)
    expect(e1.key).not.toEqual(e1.key.slice().reverse())
    // The number is in the derivation, so the same secret at another number
    // is another epoch.
    expect(e2.id).not.toBe(e1.id)
    expect(e2.key).not.toEqual(e1.key)
    // And the id says nothing about the key.
    expect(e1.id).not.toBe(Array.from(e1.key, (b) => b.toString(16).padStart(2, '0')).join(''))
  })

  it('refuses a short secret and a silly epoch number', () => {
    expect(() => deriveEpoch({ epoch: 1, secret: new Uint8Array(16) })).toThrow(/32 bytes/)
    expect(() => deriveEpoch({ epoch: -1, secret: ROOM_SECRET })).toThrow(/epoch/)
    expect(() => deriveEpoch({ epoch: 1.5, secret: ROOM_SECRET })).toThrow(/epoch/)
  })
})

describe('rekey events', () => {
  const authoritySk = generateSecretKey()
  const authority = getPublicKey(authoritySk)
  const current = deriveEpoch({ epoch: 0, secret: ROOM_SECRET })
  const keptSk = generateSecretKey()
  const kept = getPublicKey(keptSk)
  const goneSk = generateSecretKey()
  const removed = getPublicKey(generateSecretKey())
  const admin = getPublicKey(generateSecretKey())
  const next = { epoch: 1, secret: generateEpochSecret() }

  function rekey(overrides: Partial<Parameters<typeof encodeRekeyEvent>[0]> = {}) {
    return encodeRekeyEvent({
      roomId,
      authoritySk,
      current,
      next,
      recipients: [kept],
      removed: [removed],
      by: admin,
      now: NOW,
      ...overrides,
    })
  }

  it('seals the new secret to a kept device, which unseals it and learns who was removed', () => {
    const event = rekey()
    expect(event.kind).toBe(KINDS.ROOM_REKEY)
    expect(event.tags).toEqual([
      ['d', roomId],
      ['epoch', '1'],
    ])
    // Nothing about who was kept or removed is on the wire.
    expect(event.content).not.toContain(kept)
    expect(event.content).not.toContain(removed)
    expect(peekRekeyEvent(event, { roomId, authority })).toBe(1)

    const notice = decodeRekeyEvent(event, { roomId, authority, current, deviceSk: keptSk })
    expect(notice).toEqual({ epoch: 1, removed: [removed], by: admin, closed: false, secret: next.secret, at: NOW })
  })

  it('a device that was not sealed for reads the notice but gets no secret', () => {
    const notice = decodeRekeyEvent(rekey(), { roomId, authority, current, deviceSk: goneSk })
    expect(notice).toBeDefined()
    expect(notice!.secret).toBeUndefined()
    expect(notice!.removed).toEqual([removed])
  })

  it('a copy sealed to one device does not open under another', () => {
    const event = rekey({ recipients: [kept, getPublicKey(goneSk)] })
    const asKept = decodeRekeyEvent(event, { roomId, authority, current, deviceSk: keptSk })!
    const asGone = decodeRekeyEvent(event, { roomId, authority, current, deviceSk: goneSk })!
    expect(asKept.secret).toEqual(next.secret)
    expect(asGone.secret).toEqual(next.secret)
    // Swap the ciphertexts and neither opens: the copy is bound to the
    // device it was sealed for, not to the event.
    const stranger = generateSecretKey()
    expect(decodeRekeyEvent(event, { roomId, authority, current, deviceSk: stranger })!.secret).toBeUndefined()
  })

  it('refuses a tampered event, a wrong authority, another room and a replay of an older epoch', () => {
    const event = rekey()
    const tampered = { ...event, tags: [['d', roomId], ['epoch', '2']] }
    expect(peekRekeyEvent(tampered, { roomId, authority })).toBeNull()
    const forged = { ...event, content: event.content.slice(0, -4) + 'AAAA' }
    expect(decodeRekeyEvent(forged, { roomId, authority, current, deviceSk: keptSk })).toBeNull()
    expect(peekRekeyEvent(event, { roomId, authority: getPublicKey(generateSecretKey()) })).toBeNull()
    expect(peekRekeyEvent(event, { roomId: deriveRoom(new Uint8Array(32).fill(8)).roomId, authority })).toBeNull()
    // Already at epoch 1: the rekey to epoch 1 is history, not an instruction.
    const atOne = deriveEpoch(next)
    expect(decodeRekeyEvent(event, { roomId, authority, current: atOne, deviceSk: keptSk })).toBeNull()
    // And the rekey to epoch 2 cannot be read from epoch 0, only from 1.
    const toTwo = encodeRekeyEvent({ roomId, authoritySk, current: atOne, next: { epoch: 2, secret: generateEpochSecret() }, recipients: [kept], removed: [], now: NOW })
    expect(peekRekeyEvent(toTwo, { roomId, authority })).toBe(2)
    expect(decodeRekeyEvent(toTwo, { roomId, authority, current, deviceSk: keptSk })).toBeNull()
    expect(decodeRekeyEvent(toTwo, { roomId, authority, current: atOne, deviceSk: keptSk })?.epoch).toBe(2)
  })

  it('a rekey moves forward by exactly one, and a close seals to nobody', () => {
    expect(() => rekey({ next: { epoch: 2, secret: generateEpochSecret() } })).toThrow(/exactly one/)
    const closing = rekey({ closed: true, removed: [], recipients: [kept] })
    const notice = decodeRekeyEvent(closing, { roomId, authority, current, deviceSk: keptSk })!
    expect(notice.closed).toBe(true)
    expect(notice.secret).toBeUndefined()
  })
})

describe('epoch requests and grants', () => {
  const authoritySk = generateSecretKey()
  const authority = getPublicKey(authoritySk)
  const deviceSk = generateSecretKey()
  const device = getPublicKey(deviceSk)
  const identity = localIdentity(generateSecretKey())

  async function credentialFor(sk: Uint8Array, id = identity) {
    return createDeviceCredential({ identity: id, devicePubkey: getPublicKey(sk), roomId, expiresAt: NOW + 3600, now })
  }

  it('a request proves the participant through its credential, and the answer is sealed to the device', async () => {
    const credential = await credentialFor(deviceSk)
    const request = encodeEpochRequest({ roomId, authority, deviceSk, roomKey, credential, now: NOW })
    expect(request.kind).toBe(KINDS.EPOCH_REQUEST)
    expect(request.content).not.toContain(identity.pubkey)
    const decoded = decodeEpochRequest(request, { roomId, authoritySk, roomKey, now: NOW })
    expect(decoded).toEqual({ device, participant: identity.pubkey, request: request.id })

    const epoch = { epoch: 3, secret: generateEpochSecret() }
    const grant = encodeEpochGrant({ roomId, authoritySk, device, request: request.id, now: NOW, epoch, removed: ['ab'.repeat(32)] })
    expect(grant.kind).toBe(KINDS.EPOCH_GRANT)
    expect(decodeEpochGrant(grant, { roomId, authority, deviceSk, request: request.id, now: NOW })).toEqual({
      epoch,
      removed: ['ab'.repeat(32)],
    })
    // Somebody else's device cannot read it, and a grant for another
    // request is not this one's.
    expect(decodeEpochGrant(grant, { roomId, authority, deviceSk: generateSecretKey(), request: request.id, now: NOW })).toBeNull()
    expect(decodeEpochGrant(grant, { roomId, authority, deviceSk, request: 'cd'.repeat(32), now: NOW })).toBeNull()
  })

  it('refuses a request whose credential is for another room, another device, or is stale', async () => {
    const credential = await credentialFor(deviceSk)
    const otherRoom = deriveRoom(new Uint8Array(32).fill(3)).roomId
    const wrongRoom = encodeEpochRequest({ roomId: otherRoom, authority, deviceSk, roomKey, credential, now: NOW })
    expect(decodeEpochRequest(wrongRoom, { roomId: otherRoom, authoritySk, roomKey, now: NOW })).toBeNull()
    const borrowed = encodeEpochRequest({ roomId, authority, deviceSk: generateSecretKey(), roomKey, credential, now: NOW })
    expect(decodeEpochRequest(borrowed, { roomId, authoritySk, roomKey, now: NOW })).toBeNull()
    const fresh = encodeEpochRequest({ roomId, authority, deviceSk, roomKey, credential, now: NOW })
    expect(decodeEpochRequest(fresh, { roomId, authoritySk, roomKey, now: NOW + 600 })).toBeNull()
  })

  it('a refusal reaches the asker as one', async () => {
    const credential = await credentialFor(deviceSk)
    const request = encodeEpochRequest({ roomId, authority, deviceSk, roomKey, credential, now: NOW })
    const grant = encodeEpochGrant({ roomId, authoritySk, device, request: request.id, now: NOW, refused: 'removed' })
    expect(decodeEpochGrant(grant, { roomId, authority, deviceSk, request: request.id, now: NOW })).toEqual({ refused: 'removed' })
  })

  it('the desk hands the current epoch to a member and refuses a removed one', async () => {
    const relay = new SimRelay()
    const epoch = { epoch: 2, secret: generateEpochSecret() }
    const removedIdentity = localIdentity(generateSecretKey())
    const desk = hostRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authoritySk,
      roomKey,
      current: () => epoch,
      removed: () => new Set([removedIdentity.pubkey]),
      now,
    })
    const granted = await requestRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authority,
      deviceSk,
      roomKey,
      credential: await credentialFor(deviceSk),
      now,
      timeoutMs: 1_000,
    })
    expect(granted.epoch).toEqual(epoch)
    expect(granted.removed).toEqual([removedIdentity.pubkey])

    const removedSk = generateSecretKey()
    await expect(
      requestRoomEpoch({
        transport: new SimTransport(relay),
        roomId,
        authority,
        deviceSk: removedSk,
        roomKey,
        credential: await credentialFor(removedSk, removedIdentity),
        now,
        timeoutMs: 1_000,
      }),
    ).rejects.toBeInstanceOf(EpochRefusedError)
    desk.close()
  })

  it('a request carries an admission proof under the room key, and one without it, or under another key, is refused', async () => {
    const credential = await credentialFor(deviceSk)
    const request = encodeEpochRequest({ roomId, authority, deviceSk, roomKey, credential, now: NOW })
    const body = JSON.parse(nip44.v2.decrypt(request.content, nip44.v2.utils.getConversationKey(authoritySk, device))) as { admission?: string }
    expect(body.admission).toBe(epochRequestAdmission({ roomKey, roomId, authority, device, createdAt: NOW }))
    expect(body.admission).not.toBe(epochRequestAdmission({ roomKey, roomId, authority, device, createdAt: NOW + 1 }))
    expect(decodeEpochRequest(request, { roomId, authoritySk, roomKey, now: NOW })).not.toBeNull()

    // A desk holding a different room key sees a proof it cannot verify.
    const otherKey = new Uint8Array(32).fill(9)
    expect(decodeEpochRequest(request, { roomId, authoritySk, roomKey: otherKey, now: NOW })).toBeNull()
    // A request made under the wrong key - a stranger guessing - is refused by the right desk.
    const strangers = encodeEpochRequest({ roomId, authority, deviceSk, roomKey: otherKey, credential, now: NOW })
    expect(decodeEpochRequest(strangers, { roomId, authoritySk, roomKey, now: NOW })).toBeNull()

    // A request from before the proof existed, or with the field stripped, is refused.
    const stripped = finalizeEvent(
      {
        kind: KINDS.EPOCH_REQUEST,
        created_at: NOW,
        tags: [['d', roomId], ['p', authority]],
        content: nip44.v2.encrypt(JSON.stringify({ v: 1, credential }), nip44.v2.utils.getConversationKey(deviceSk, authority)),
      },
      deviceSk,
    )
    expect(decodeEpochRequest(stripped, { roomId, authoritySk, roomKey, now: NOW })).toBeNull()
    expect(decodeEpochRequest(stripped, {
      roomId,
      authoritySk,
      roomKey,
      now: NOW,
      legacyParticipants: new Set([identity.pubkey]),
    })).toEqual({ device, participant: identity.pubkey, request: stripped.id })
    expect(decodeEpochRequest(stripped, {
      roomId,
      authoritySk,
      roomKey,
      now: NOW,
      legacyParticipants: new Set([localIdentity(generateSecretKey()).pubkey]),
    })).toBeNull()
  })

  it('the desk does not answer a stranger who has the room id and the authority but no room key', async () => {
    const relay = new SimRelay()
    const epoch = { epoch: 2, secret: generateEpochSecret() }
    const desk = hostRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authoritySk,
      roomKey,
      current: () => epoch,
      removed: () => new Set(),
      now,
    })
    // Everything a relay reader can see: the room id and the authority's
    // pubkey off a rekey event. A participant key and a credential are
    // theirs to mint. The room key is not.
    const strangerSk = generateSecretKey()
    const strangerIdentity = localIdentity(generateSecretKey())
    await expect(
      requestRoomEpoch({
        transport: new SimTransport(relay),
        roomId,
        authority,
        deviceSk: strangerSk,
        roomKey: new Uint8Array(32).fill(1),
        credential: await credentialFor(strangerSk, strangerIdentity),
        now,
        timeoutMs: 60,
        retryMs: 20,
      }),
    ).rejects.toThrow(/not answering/)
    expect(relay.published.filter((e) => e.kind === KINDS.EPOCH_GRANT)).toHaveLength(0)
    desk.close()
  })

  it('nobody answering is a bounded failure with a reason', async () => {
    const relay = new SimRelay()
    await expect(
      requestRoomEpoch({
        transport: new SimTransport(relay),
        roomId,
        authority,
        deviceSk,
      roomKey,
        credential: await credentialFor(deviceSk),
        now,
        timeoutMs: 30,
        retryMs: 10,
      }),
    ).rejects.toThrow(/not answering/)
  })
})

describe('the admin list', () => {
  it('verifies against the authority and nobody else, for this room and epoch', () => {
    const authoritySk = generateSecretKey()
    const authority = getPublicKey(authoritySk)
    const admins = ['CD'.repeat(32), 'ab'.repeat(32)]
    const sig = signAdmins({ roomId, epoch: 1, admins, authoritySk })
    expect(verifyAdmins({ roomId, epoch: 1, admins, sig, authority })).toBe(true)
    // Order and case do not matter; the list does.
    expect(verifyAdmins({ roomId, epoch: 1, admins: ['ab'.repeat(32), 'cd'.repeat(32)], sig, authority })).toBe(true)
    expect(verifyAdmins({ roomId, epoch: 1, admins: ['ab'.repeat(32)], sig, authority })).toBe(false)
    expect(verifyAdmins({ roomId, epoch: 2, admins, sig, authority })).toBe(false)
    expect(verifyAdmins({ roomId, epoch: 1, admins, sig, authority: getPublicKey(generateSecretKey()) })).toBe(false)
    expect(verifyAdmins({ roomId, epoch: 1, admins, sig: 'zz', authority })).toBe(false)
  })
})

describe('the channel list', () => {
  it('verifies against the authority and nobody else, for this room and epoch', () => {
    const authoritySk = generateSecretKey()
    const authority = getPublicKey(authoritySk)
    const channels = ['shipping', 'design']
    const sig = signChannels({ roomId, epoch: 1, channels, authoritySk })
    expect(verifyChannels({ roomId, epoch: 1, channels, sig, authority })).toBe(true)
    // Order does not matter; the set does.
    expect(verifyChannels({ roomId, epoch: 1, channels: ['design', 'shipping'], sig, authority })).toBe(true)
    expect(verifyChannels({ roomId, epoch: 1, channels: ['design'], sig, authority })).toBe(false)
    // A member holding the room key must not be able to add a channel by
    // replaying a list the authority signed at another epoch.
    expect(verifyChannels({ roomId, epoch: 2, channels, sig, authority })).toBe(false)
    expect(verifyChannels({ roomId, epoch: 1, channels, sig, authority: getPublicKey(generateSecretKey()) })).toBe(false)
    expect(verifyChannels({ roomId, epoch: 1, channels, sig: 'zz', authority })).toBe(false)
  })

  it('refuses a name that cannot survive being a label and a thread id', () => {
    for (const bad of ['', ' ', 'Design', 'has space', '-leading', 'e'.repeat(65), 'emoji🙂', 'under_score']) {
      expect(() => canonicalChannels([bad]), JSON.stringify(bad)).toThrow()
    }
    expect(canonicalChannels(['shipping', 'design', 'shipping'])).toEqual(['design', 'shipping'])
  })

  it('refuses the three names the room already means something by', () => {
    for (const reserved of RESERVED_CHANNELS) {
      expect(() => canonicalChannels([reserved]), reserved).toThrow()
    }
  })

  it('never throws on rubbish, because it runs on whatever a relay hands over', () => {
    const authority = getPublicKey(generateSecretKey())
    for (const rubbish of [['Design'], ['agents'], [null], [{}]]) {
      expect(
        verifyChannels({ roomId, epoch: 1, channels: rubbish as string[], sig: 'ab'.repeat(64), authority }),
      ).toBe(false)
    }
  })
})
