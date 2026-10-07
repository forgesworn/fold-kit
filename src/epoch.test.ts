import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { SimRelay, SimTransport } from '../test/sim-relay.js'
import { createDeviceCredential } from './credential.js'
import { localIdentity } from './identity.js'
import { deriveRoom } from './room.js'
import { KINDS } from './kinds.js'
import { base64urlnopad } from '@scure/base'
import {
  EpochRefusedError,
  HISTORY_WINDOW_SECONDS,
  MAX_HISTORY_EPOCHS,
  decodeEpochGrant,
  decodeEpochRequest,
  decodeRekeyEvent,
  deriveEpoch,
  encodeEpochGrant,
  encodeEpochRequest,
  epochRequestAdmission,
  epochsInWindow,
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
  type LeftEpoch,
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
      known: (p) => p === identity.pubkey,
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

describe('the known-members gate (#207)', () => {
  const authoritySk = generateSecretKey()
  const authority = getPublicKey(authoritySk)
  const member = localIdentity(generateSecretKey())
  const gone = localIdentity(generateSecretKey())
  const epoch = { epoch: 2, secret: generateEpochSecret() }

  async function ask(relay: SimRelay, who: ReturnType<typeof localIdentity>, extra: Partial<Parameters<typeof requestRoomEpoch>[0]> = {}) {
    const sk = generateSecretKey()
    return requestRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authority,
      deviceSk: sk,
      roomKey,
      credential: await createDeviceCredential({ identity: who, devicePubkey: getPublicKey(sk), roomId, expiresAt: NOW + 3600, now }),
      now,
      timeoutMs: 300,
      retryMs: 20,
      ...extra,
    })
  }

  function desk(relay: SimRelay, extra: Partial<Parameters<typeof hostRoomEpoch>[0]> = {}) {
    return hostRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authoritySk,
      roomKey,
      current: () => epoch,
      removed: () => new Set([gone.pubkey]),
      known: (p) => p === member.pubkey,
      now,
      ...extra,
    })
  }

  it('a rekey carries the member list it was given, less the removed, and nothing when not given one', () => {
    const current = deriveEpoch({ epoch: 0, secret: ROOM_SECRET })
    const keptSk = generateSecretKey()
    const base = { roomId, authoritySk, current, next: { epoch: 1, secret: generateEpochSecret() }, recipients: [getPublicKey(keptSk)], removed: [gone.pubkey], now: NOW }
    const listed = encodeRekeyEvent({ ...base, members: [member.pubkey.toUpperCase(), gone.pubkey, member.pubkey] })
    expect(decodeRekeyEvent(listed, { roomId, authority, current, deviceSk: keptSk })?.members).toEqual([member.pubkey])
    const unlisted = encodeRekeyEvent(base)
    const body = JSON.parse(nip44.v2.decrypt(unlisted.content, current.key)) as Record<string, unknown>
    expect('members' in body).toBe(false)
    expect(decodeRekeyEvent(unlisted, { roomId, authority, current, deviceSk: keptSk })?.members).toBeUndefined()
  })

  it('a removed person back under a fresh key is told the room does not know them, and gets no epoch', async () => {
    const relay = new SimRelay()
    const unknownAtDesk: string[] = []
    const handle = desk(relay, { onUnknown: (r) => unknownAtDesk.push(r.participant) })
    const fresh = localIdentity(generateSecretKey())
    let toldUnknown = 0
    const refusal = await ask(relay, fresh, { onUnknown: () => { toldUnknown += 1 } }).catch((e: unknown) => e)
    expect(refusal).toBeInstanceOf(EpochRefusedError)
    expect((refusal as EpochRefusedError).refused).toBe('unknown')
    expect(toldUnknown).toBe(1)
    // Asked many times while it waited, reported once, answered once.
    expect(unknownAtDesk).toEqual([fresh.pubkey])
    expect(relay.published.filter((e) => e.kind === KINDS.EPOCH_GRANT)).toHaveLength(1)
    handle.close()
  })

  it('a member the room knows is granted, and told who the room knows', async () => {
    const relay = new SimRelay()
    const handle = desk(relay, { members: () => [member.pubkey] })
    const grant = await ask(relay, member)
    expect(grant.epoch).toEqual(epoch)
    expect(grant.members).toEqual([member.pubkey])
    handle.close()
  })

  it('somebody let in while they wait is granted on their next ask', async () => {
    const relay = new SimRelay()
    const letIn = new Set<string>()
    const handle = desk(relay, { known: (p) => letIn.has(p), onUnknown: (r) => letIn.add(r.participant) })
    const grant = await ask(relay, localIdentity(generateSecretKey()))
    expect(grant.epoch).toEqual(epoch)
    handle.close()
  })

  it('before anybody is removed, a newcomer is granted as before, with or without `known`', async () => {
    const relay = new SimRelay()
    const handle = desk(relay, { removed: () => new Set(), known: undefined })
    expect((await ask(relay, localIdentity(generateSecretKey()))).epoch).toEqual(epoch)
    handle.close()
  })

  it('after a removal, a desk with no `known` lets nobody through', async () => {
    const relay = new SimRelay()
    const handle = desk(relay, { known: undefined })
    await expect(ask(relay, member)).rejects.toMatchObject({ refused: 'unknown' })
    handle.close()
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

describe('a conference room\'s epoch events', () => {
  const authoritySk = generateSecretKey()
  const authority = getPublicKey(authoritySk)
  const deviceSk = generateSecretKey()
  const device = getPublicKey(deviceSk)
  const identity = localIdentity(generateSecretKey())
  const ends = NOW + 86_400
  const expiration = ['expiration', String(ends)]

  it('a rekey, a request and a grant all carry the room\'s end, and still decode', async () => {
    const current = deriveEpoch({ epoch: 0, secret: ROOM_SECRET })
    const next = { epoch: 1, secret: generateEpochSecret() }
    const rekey = encodeRekeyEvent({ roomId, authoritySk, current, next, recipients: [device], removed: [], now: NOW, expiresAt: ends })
    expect(rekey.tags).toEqual([['d', roomId], ['epoch', '1'], expiration])
    expect(decodeRekeyEvent(rekey, { roomId, authority, current, deviceSk })).toMatchObject({ epoch: 1, secret: next.secret })

    const credential = await createDeviceCredential({ identity, devicePubkey: device, roomId, expiresAt: NOW + 3600, now })
    const request = encodeEpochRequest({ roomId, authority, deviceSk, roomKey, credential, now: NOW, expiresAt: ends })
    expect(request.tags).toEqual([['d', roomId], ['p', authority], expiration])
    expect(decodeEpochRequest(request, { roomId, authoritySk, roomKey, now: NOW })).not.toBeNull()

    const grant = encodeEpochGrant({ roomId, authoritySk, device, request: request.id, now: NOW, refused: 'closed', expiresAt: ends })
    expect(grant.tags).toEqual([['d', roomId], ['p', device], expiration])
    expect(decodeEpochGrant(grant, { roomId, authority, deviceSk, request: request.id, now: NOW })).toEqual({ refused: 'closed' })
  })

  it('without an end, the tags are exactly what they were', () => {
    const current = deriveEpoch({ epoch: 0, secret: ROOM_SECRET })
    const rekey = encodeRekeyEvent({ roomId, authoritySk, current, next: { epoch: 1, secret: generateEpochSecret() }, recipients: [device], removed: [], now: NOW })
    expect(rekey.tags).toEqual([['d', roomId], ['epoch', '1']])
  })

  it('the desk and the asker pass the end through to what they publish', async () => {
    const relay = new SimRelay()
    const epoch = { epoch: 2, secret: generateEpochSecret() }
    const desk = hostRoomEpoch({ transport: new SimTransport(relay), roomId, authoritySk, roomKey, current: () => epoch, removed: () => new Set(), now, expiresAt: ends })
    const credential = await createDeviceCredential({ identity, devicePubkey: device, roomId, expiresAt: NOW + 3600, now })
    await requestRoomEpoch({ transport: new SimTransport(relay), roomId, authority, deviceSk, roomKey, credential, now, timeoutMs: 1_000, expiresAt: ends })
    desk.close()
    expect(relay.published.map((e) => e.kind).sort()).toEqual([KINDS.EPOCH_REQUEST, KINDS.EPOCH_GRANT].sort())
    for (const event of relay.published) expect(event.tags).toContainEqual(expiration)
  })
})

describe('scheduled rekeys', () => {
  const authoritySk = generateSecretKey()
  const authority = getPublicKey(authoritySk)
  const current = deriveEpoch({ epoch: 0, secret: ROOM_SECRET })
  const keptSk = generateSecretKey()
  const kept = getPublicKey(keptSk)
  const member = getPublicKey(generateSecretKey())
  const gone = getPublicKey(generateSecretKey())
  const next = { epoch: 1, secret: generateEpochSecret() }
  const base = { roomId, authoritySk, current, next, recipients: [kept], removed: [] as string[], commit: true, members: [member], now: NOW }
  const bodyOf = (event: { content: string }) => JSON.parse(nip44.v2.decrypt(event.content, current.key)) as Record<string, unknown>

  /** A rekey signed by the authority whose body says whatever it is told:
   *  what a broken or older authority could publish. */
  function signedBody(body: Record<string, unknown>) {
    return finalizeEvent(
      { kind: KINDS.ROOM_REKEY, created_at: NOW, tags: [['d', roomId], ['epoch', '1']], content: nip44.v2.encrypt(JSON.stringify(body), current.key) },
      authoritySk,
    )
  }

  it('carries the marker inside the body, and the reader reports it with the secret', () => {
    const event = encodeRekeyEvent({ ...base, scheduled: true })
    // Inside the encrypted body, so a relay cannot tell it from a removal.
    expect(event.tags).toEqual([['d', roomId], ['epoch', '1']])
    expect(bodyOf(event).scheduled).toBe(true)
    const notice = decodeRekeyEvent(event, { roomId, authority, current, deviceSk: keptSk })
    expect(notice).toEqual({ epoch: 1, removed: [], closed: false, scheduled: true, members: [member], secret: next.secret, at: NOW })
  })

  it('without the flag, or with it false, the body is exactly what it was', () => {
    const plain = bodyOf(encodeRekeyEvent(base))
    const unflagged = bodyOf(encodeRekeyEvent({ ...base, scheduled: false }))
    expect('scheduled' in plain).toBe(false)
    // The keys map seals afresh each time; everything else is the same text.
    const strip = (b: Record<string, unknown>) => JSON.stringify({ ...b, keys: Object.keys(b.keys as object) })
    expect(strip(unflagged)).toBe(strip(plain))
    expect(decodeRekeyEvent(encodeRekeyEvent(base), { roomId, authority, current, deviceSk: keptSk })?.scheduled).toBeUndefined()
  })

  it('refuses to mark a rekey that removes somebody or closes the room', () => {
    expect(() => encodeRekeyEvent({ ...base, scheduled: true, removed: [gone] })).toThrow(/scheduled/)
    expect(() => encodeRekeyEvent({ ...base, scheduled: true, removed: [gone.toUpperCase(), gone] })).toThrow(/scheduled/)
    expect(() => encodeRekeyEvent({ ...base, scheduled: true, closed: true })).toThrow(/scheduled/)
  })

  it('a body that contradicts itself is read as not scheduled, so the removal or the close is still announced', () => {
    const keys = {}
    const withRemoval = decodeRekeyEvent(signedBody({ v: 1, epoch: 1, removed: [gone], scheduled: true, keys }), { roomId, authority, current, deviceSk: keptSk })
    expect(withRemoval).toMatchObject({ epoch: 1, removed: [gone], closed: false })
    expect(withRemoval?.scheduled).toBeUndefined()
    const closing = decodeRekeyEvent(signedBody({ v: 1, epoch: 1, removed: [], closed: true, scheduled: true, keys }), { roomId, authority, current, deviceSk: keptSk })
    expect(closing).toMatchObject({ epoch: 1, closed: true })
    expect(closing?.scheduled).toBeUndefined()
    // Only `true` marks it.
    const odd = decodeRekeyEvent(signedBody({ v: 1, epoch: 1, removed: [], scheduled: 'yes', keys }), { roomId, authority, current, deviceSk: keptSk })
    expect(odd).not.toBeNull()
    expect(odd?.scheduled).toBeUndefined()
  })
})

describe('self-destructing closures', () => {
  const authoritySk = generateSecretKey()
  const authority = getPublicKey(authoritySk)
  const current = deriveEpoch({ epoch: 0, secret: ROOM_SECRET })
  const keptSk = generateSecretKey()
  const kept = getPublicKey(keptSk)
  const gone = getPublicKey(generateSecretKey())
  const next = { epoch: 1, secret: generateEpochSecret() }
  const base = { roomId, authoritySk, current, next, recipients: [kept], removed: [] as string[], now: NOW }
  const bodyOf = (event: { content: string }) => JSON.parse(nip44.v2.decrypt(event.content, current.key)) as Record<string, unknown>
  const read = (event: Parameters<typeof decodeRekeyEvent>[0]) => decodeRekeyEvent(event, { roomId, authority, current, deviceSk: keptSk })

  /** A rekey signed by the authority whose body says whatever it is told. */
  function signedBody(body: Record<string, unknown>) {
    return finalizeEvent(
      { kind: KINDS.ROOM_REKEY, created_at: NOW, tags: [['d', roomId], ['epoch', '1']], content: nip44.v2.encrypt(JSON.stringify(body), current.key) },
      authoritySk,
    )
  }

  it('carries the flag inside the closing body, after closed, and the reader reports it', () => {
    const event = encodeRekeyEvent({ ...base, closed: true, destruct: true })
    expect(event.tags).toEqual([['d', roomId], ['epoch', '1']])
    expect(event.content).not.toContain('destruct')
    expect(bodyOf(event)).toEqual({ v: 1, epoch: 1, removed: [], closed: true, destruct: true, keys: {} })
    expect(Object.keys(bodyOf(event))).toEqual(['v', 'epoch', 'removed', 'closed', 'destruct', 'keys'])
    expect(read(event)).toEqual({ epoch: 1, removed: [], closed: true, destruct: true, at: NOW })
  })

  it('without the flag, or with it false, a closure is byte for byte what 0.8.0 wrote', () => {
    // A closure seals nothing, so the whole plaintext is fixed and comparable.
    for (const destruct of [undefined, false]) {
      const event = encodeRekeyEvent({ ...base, closed: true, destruct })
      expect(JSON.stringify(bodyOf(event))).toBe('{"v":1,"epoch":1,"removed":[],"closed":true,"keys":{}}')
      expect(read(event)).toEqual({ epoch: 1, removed: [], closed: true, at: NOW })
    }
  })

  it('refuses to self-destruct a room it is not closing, and a scheduled turn never closes', () => {
    expect(() => encodeRekeyEvent({ ...base, destruct: true })).toThrow(/only a closing rekey/)
    expect(() => encodeRekeyEvent({ ...base, destruct: true, removed: [gone] })).toThrow(/only a closing rekey/)
    expect(() => encodeRekeyEvent({ ...base, destruct: true, scheduled: true })).toThrow(/scheduled|closing/)
    expect(() => encodeRekeyEvent({ ...base, destruct: true, closed: true, scheduled: true })).toThrow(/scheduled/)
  })

  it('a flag beside an open room is not believed, and the rekey is still read', () => {
    // Refusing the rekey would strand the device in the old epoch and hide
    // a removal; a 0.8.0 reader reads it too. So the flag is dropped instead.
    const withRemoval = read(signedBody({ v: 1, epoch: 1, removed: [gone], destruct: true, keys: {} }))
    expect(withRemoval).toEqual({ epoch: 1, removed: [gone], closed: false, at: NOW })
    const scheduled = read(signedBody({ v: 1, epoch: 1, removed: [], destruct: true, scheduled: true, keys: {} }))
    expect(scheduled).toEqual({ epoch: 1, removed: [], closed: false, scheduled: true, at: NOW })
    // Only `true` marks it, even on a close.
    for (const destruct of ['true', 1, null, {}]) {
      expect(read(signedBody({ v: 1, epoch: 1, removed: [], closed: true, destruct, keys: {} }))).toEqual({ epoch: 1, removed: [], closed: true, at: NOW })
    }
    // A closing body that also claims to be scheduled is a close, and self-destructs.
    expect(read(signedBody({ v: 1, epoch: 1, removed: [], closed: true, destruct: true, scheduled: true, keys: {} })))
      .toEqual({ epoch: 1, removed: [], closed: true, destruct: true, at: NOW })
  })
})

describe('the history window', () => {
  const day = 86_400

  it('keeps an epoch left exactly 30 days ago, and not one a second older', () => {
    expect(HISTORY_WINDOW_SECONDS).toBe(30 * day)
    const left = [
      { epoch: 1, leftAt: NOW - HISTORY_WINDOW_SECONDS - 1 },
      { epoch: 2, leftAt: NOW - HISTORY_WINDOW_SECONDS },
      { epoch: 3, leftAt: NOW - day },
    ]
    expect(epochsInWindow(left, NOW).map((e) => e.epoch)).toEqual([3, 2])
  })

  it('keeps the newest 16 however many fall inside the window', () => {
    expect(MAX_HISTORY_EPOCHS).toBe(16)
    const left = Array.from({ length: 20 }, (_, i) => ({ epoch: i + 1, leftAt: NOW - (20 - i) * 3600 }))
    const kept = epochsInWindow(left, NOW)
    expect(kept).toHaveLength(16)
    expect(kept[0]!.epoch).toBe(20)
    expect(kept.at(-1)!.epoch).toBe(5)
  })

  it('sorts newest first, keeps the first of a doubled epoch, and hands back what it was given', () => {
    const secret = generateEpochSecret()
    const first = { epoch: 4, secret, leftAt: NOW - 10 }
    const kept = epochsInWindow([{ epoch: 2, secret, leftAt: NOW - 30 }, first, { epoch: 4, secret, leftAt: NOW - 5 }, { epoch: 3, secret, leftAt: NOW - 20 }], NOW)
    expect(kept.map((e) => e.epoch)).toEqual([4, 3, 2])
    expect(kept[0]).toBe(first)
  })

  it('drops an entry with no usable number or time, and never throws', () => {
    const left = [
      { epoch: 1.5, leftAt: NOW },
      { epoch: -1, leftAt: NOW },
      { epoch: 2, leftAt: Number.NaN },
      null as unknown as { epoch: number; leftAt: number },
      { epoch: 3, leftAt: NOW },
    ]
    expect(epochsInWindow(left, NOW).map((e) => e.epoch)).toEqual([3])
    expect(epochsInWindow([], NOW)).toEqual([])
  })
})

describe('an authority grant carries the window', () => {
  const authoritySk = generateSecretKey()
  const authority = getPublicKey(authoritySk)
  const deviceSk = generateSecretKey()
  const device = getPublicKey(deviceSk)
  const identity = localIdentity(generateSecretKey())
  const request = 'ef'.repeat(32)
  const granted = { epoch: 18, secret: generateEpochSecret() }
  const left = (epoch: number, leftAt = NOW - (18 - epoch) * 3600): LeftEpoch => ({ epoch, secret: generateEpochSecret(), leftAt })
  const sixteen = Array.from({ length: 16 }, (_, i) => left(i + 2))
  const grant = (passed?: readonly LeftEpoch[]) => encodeEpochGrant({ roomId, authoritySk, device, request, now: NOW, epoch: granted, removed: [], passed })
  const read = (event: ReturnType<typeof grant>) => decodeEpochGrant(event, { roomId, authority, deviceSk, request, now: NOW })
  const bodyOf = (event: { content: string }) =>
    JSON.parse(nip44.v2.decrypt(event.content, nip44.v2.utils.getConversationKey(deviceSk, authority))) as Record<string, unknown>
  /** A grant the authority signed with whatever `passed` it is told. */
  const handBuilt = (passed: unknown) =>
    finalizeEvent(
      {
        kind: KINDS.EPOCH_GRANT,
        created_at: NOW,
        tags: [['d', roomId], ['p', device]],
        content: nip44.v2.encrypt(
          JSON.stringify({ v: 1, request, epoch: 18, secret: base64urlnopad.encode(granted.secret), removed: [], passed }),
          nip44.v2.utils.getConversationKey(authoritySk, device),
        ),
      },
      authoritySk,
    )

  it('round-trips up to 16 left epochs, oldest first, with when each was left', () => {
    const shuffled = [...sixteen].reverse()
    const decoded = read(grant(shuffled))
    expect(decoded).toEqual({ epoch: granted, removed: [], passed: sixteen })
    const wire = bodyOf(grant(shuffled)).passed as Array<Record<string, unknown>>
    expect(wire.map((e) => e.epoch)).toEqual(sixteen.map((e) => e.epoch))
    expect(Object.keys(wire[0]!)).toEqual(['epoch', 'secret', 'left'])
  })

  it('with nothing to carry, the body is as before', () => {
    expect('passed' in bodyOf(grant())).toBe(false)
    expect('passed' in bodyOf(grant([]))).toBe(false)
    expect(read(grant([]))).toEqual({ epoch: granted, removed: [] })
    const refusal = encodeEpochGrant({ roomId, authoritySk, device, request, now: NOW, refused: 'removed', passed: sixteen })
    expect(bodyOf(refusal)).toEqual({ v: 1, request, refused: 'removed' })
  })

  it('refuses 17, epoch 0, an epoch not before the one granted, a doubled epoch, a short secret and a bad time', () => {
    expect(() => grant([...sixteen, left(1)])).toThrow(/at most 16/)
    expect(() => grant([{ epoch: 0, secret: ROOM_SECRET, leftAt: NOW }])).toThrow(/after epoch 0/)
    expect(() => grant([left(18)])).toThrow(/before the one granted/)
    expect(() => grant([left(5), left(5)])).toThrow(/once/)
    expect(() => grant([{ epoch: 5, secret: new Uint8Array(16), leftAt: NOW }])).toThrow(/32 bytes/)
    expect(() => grant([{ ...left(5), leftAt: -1 }])).toThrow(/leftAt/)
    expect(() => grant([{ ...left(5), leftAt: 1.5 }])).toThrow(/leftAt/)
  })

  it('a malformed list costs the history, not the grant', () => {
    const wire = (e: LeftEpoch) => ({ epoch: e.epoch, secret: base64urlnopad.encode(e.secret), left: e.leftAt })
    const good = sixteen.map(wire)
    expect(read(handBuilt(good))).toEqual({ epoch: granted, removed: [], passed: sixteen })
    for (const bad of [
      [...good, wire(left(1))],
      [good[1], good[0]],
      [good[0], good[0]],
      [{ ...good[0], epoch: 0 }],
      [{ ...good[0], epoch: 18 }],
      [{ ...good[0], secret: base64urlnopad.encode(new Uint8Array(31)) }],
      [{ ...good[0], secret: '!!' }],
      [{ ...good[0], left: -5 }],
      [{ epoch: 2, secret: good[0]!.secret }],
      [null],
      'everything',
    ]) {
      expect(read(handBuilt(bad))).toEqual({ epoch: granted, removed: [] })
    }
  })

  it('the desk hands its window to whoever it grants, and leaves out what it could not carry', async () => {
    const relay = new SimRelay()
    const old = left(3, NOW - HISTORY_WINDOW_SECONDS - 1)
    const kept = [left(16), left(17)]
    const desk = hostRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authoritySk,
      roomKey,
      current: () => granted,
      removed: () => new Set(),
      past: () => [old, ...kept, { epoch: 0, secret: ROOM_SECRET, leftAt: NOW }, left(18), { epoch: 9, secret: new Uint8Array(3), leftAt: NOW }],
      now,
    })
    const answer = await requestRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authority,
      deviceSk,
      roomKey,
      credential: await createDeviceCredential({ identity, devicePubkey: device, roomId, expiresAt: NOW + 3600, now }),
      now,
      timeoutMs: 1_000,
    })
    desk.close()
    expect(answer.epoch).toEqual(granted)
    expect(answer.passed).toEqual(kept)
  })

  it('a desk whose past() throws, or runs long, still grants', async () => {
    for (const [past, expected] of [
      [() => { throw new Error('no history') }, undefined],
      [() => Array.from({ length: 20 }, (_, i) => left(i + 1, NOW - 60)).filter((e) => e.epoch < 18), 16],
    ] as const) {
      const relay = new SimRelay()
      const desk = hostRoomEpoch({ transport: new SimTransport(relay), roomId, authoritySk, roomKey, current: () => granted, removed: () => new Set(), past, now })
      const answer = await requestRoomEpoch({
        transport: new SimTransport(relay),
        roomId,
        authority,
        deviceSk,
        roomKey,
        credential: await createDeviceCredential({ identity, devicePubkey: device, roomId, expiresAt: NOW + 3600, now }),
        now,
        timeoutMs: 1_000,
      })
      desk.close()
      expect(answer.epoch).toEqual(granted)
      expect(answer.passed?.length).toBe(expected)
    }
  })

  it('a desk with no past() grants exactly as before', async () => {
    const relay = new SimRelay()
    const desk = hostRoomEpoch({ transport: new SimTransport(relay), roomId, authoritySk, roomKey, current: () => granted, removed: () => new Set(), now })
    const answer = await requestRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authority,
      deviceSk,
      roomKey,
      credential: await createDeviceCredential({ identity, devicePubkey: device, roomId, expiresAt: NOW + 3600, now }),
      now,
      timeoutMs: 1_000,
    })
    desk.close()
    expect(answer).toEqual({ epoch: granted, removed: [] })
    const sent = relay.published.find((e) => e.kind === KINDS.EPOCH_GRANT)!
    expect('passed' in bodyOf(sent)).toBe(false)
  })
})
