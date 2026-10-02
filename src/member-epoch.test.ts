import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { SimRelay, SimTransport } from '../test/sim-relay.js'
import { createDeviceCredential } from './credential.js'
import { localIdentity } from './identity.js'
import { deriveRoom } from './room.js'
import {
  decodeRekeyEvent,
  deriveEpoch,
  encodeRekeyEvent,
  generateEpochSecret,
  hostRoomEpoch,
  requestRoomEpoch,
  type EpochKeys,
  type RoomEpoch,
} from './epoch.js'
import { epochCommitment } from './epoch-commit.js'
import {
  MEMBER_EPOCH_KINDS,
  decodeMemberEpochGrant,
  decodeMemberEpochRequest,
  encodeMemberEpochGrant,
  encodeMemberEpochRequest,
  hostMemberEpochDesk,
  memberEpochSource,
  readRekeyEvidence,
  requestMemberEpoch,
  type MemberEpochRequest,
} from './member-epoch.js'

const NOW = 1_800_000_000
const now = () => NOW
const ROOM_SECRET = new Uint8Array(32).fill(7)
const { roomId, roomKey } = deriveRoom(ROOM_SECRET)
const E0: RoomEpoch = { epoch: 0, secret: ROOM_SECRET }

const authoritySk = generateSecretKey()
const authority = getPublicKey(authoritySk)

/** Participants: a member who answers, a requester, and one who is removed. */
const member = localIdentity(generateSecretKey())
const memberDeviceSk = generateSecretKey()
const requester = localIdentity(generateSecretKey())
const requesterDeviceSk = generateSecretKey()
const requesterDevice = getPublicKey(requesterDeviceSk)
const gone = localIdentity(generateSecretKey())
const goneDeviceSk = generateSecretKey()

async function credentialFor(deviceSk: Uint8Array, id: ReturnType<typeof localIdentity>) {
  return createDeviceCredential({ identity: id, devicePubkey: getPublicKey(deviceSk), roomId, expiresAt: NOW + 3600, now })
}

interface Chain {
  epochs: RoomEpoch[]
  rekeys: Event[]
}

/** Rekey the room from epoch 0 `steps` times. `commit` and `removed` per step. */
function buildChain(steps: { commit?: boolean; removed?: string[]; closed?: boolean }[]): Chain {
  const epochs: RoomEpoch[] = [E0]
  const rekeys: Event[] = []
  steps.forEach((step, i) => {
    const next = { epoch: i + 1, secret: generateEpochSecret() }
    rekeys.push(
      encodeRekeyEvent({
        roomId,
        authoritySk,
        current: deriveEpoch(epochs[i]!),
        next,
        // The requester's new device is in none of them: that is the incident.
        recipients: [getPublicKey(memberDeviceSk)],
        removed: step.removed ?? [],
        closed: step.closed,
        commit: step.commit,
        now: NOW - 100 + i,
      }),
    )
    epochs.push(next)
  })
  return { epochs, rekeys }
}

function keysOf(epoch: RoomEpoch): EpochKeys {
  return deriveEpoch(epoch)
}

describe('the epoch commitment in a rekey', () => {
  it('is written only when asked, is read by a member at the epoch left, and is ignored by the old decoder', () => {
    const { epochs, rekeys } = buildChain([{ commit: true }])
    const evidence = readRekeyEvidence(rekeys[0]!, { roomId, authority, previous: keysOf(E0) })
    expect(evidence?.commit).toBe(epochCommitment(roomId, 1, epochs[1]!.secret))
    const notice = decodeRekeyEvent(rekeys[0]!, { roomId, authority, current: keysOf(E0), deviceSk: memberDeviceSk })
    expect(notice?.secret).toEqual(epochs[1]!.secret)

    const legacy = buildChain([{}])
    const body = JSON.parse(nip44.v2.decrypt(legacy.rekeys[0]!.content, keysOf(E0).key)) as Record<string, unknown>
    expect(Object.keys(body)).toEqual(['v', 'epoch', 'removed', 'keys'])
    expect(readRekeyEvidence(legacy.rekeys[0]!, { roomId, authority, previous: keysOf(E0) })?.commit).toBeUndefined()
  })

  it('is bound to the room, the epoch and the secret', () => {
    const secret = generateEpochSecret()
    const other = deriveRoom(new Uint8Array(32).fill(3)).roomId
    const c = epochCommitment(roomId, 1, secret)
    expect(c).toMatch(/^[0-9a-f]{64}$/)
    expect(epochCommitment(other, 1, secret)).not.toBe(c)
    expect(epochCommitment(roomId, 2, secret)).not.toBe(c)
    expect(epochCommitment(roomId, 1, generateEpochSecret())).not.toBe(c)
    expect(epochCommitment(roomId.toUpperCase(), 1, secret)).toBe(c)
  })
})

describe('member epoch requests', () => {
  it('any admitted device reads one; a stranger without the room key cannot, and a borrowed credential is refused', async () => {
    const credential = await credentialFor(requesterDeviceSk, requester)
    const request = encodeMemberEpochRequest({ roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential, have: 0, now: NOW })
    expect(request.kind).toBe(MEMBER_EPOCH_KINDS.REQUEST)
    expect(request.tags).toEqual([['d', roomId]])
    expect(request.content).not.toContain(requester.pubkey)
    expect(decodeMemberEpochRequest(request, { roomId, authority, roomKey, now: NOW })).toEqual({
      device: requesterDevice,
      participant: requester.pubkey,
      request: request.id,
      have: 0,
    })
    expect(decodeMemberEpochRequest(request, { roomId, authority, roomKey: new Uint8Array(32).fill(1), now: NOW })).toBeNull()
    expect(decodeMemberEpochRequest(request, { roomId, authority, roomKey, now: NOW + 600 })).toBeNull()
    const borrowed = encodeMemberEpochRequest({ roomId, authority, deviceSk: generateSecretKey(), roomKey, credential, have: 0, now: NOW })
    expect(decodeMemberEpochRequest(borrowed, { roomId, authority, roomKey, now: NOW })).toBeNull()
  })
})

describe('member epoch grants: what the requester accepts', () => {
  const requestId = 'ab'.repeat(32)
  const requests = new Set([requestId])

  function grantFrom(chain: Chain, from: number, opts: { tamper?: (epochs: RoomEpoch[]) => RoomEpoch[] } = {}) {
    const epochs = chain.epochs.slice(from + 1)
    return encodeMemberEpochGrant({
      roomId,
      deviceSk: memberDeviceSk,
      device: requesterDevice,
      request: requestId,
      epochs: opts.tamper ? opts.tamper(epochs) : epochs,
      rekeys: chain.rekeys.slice(from),
      now: NOW,
    })
  }

  function decode(grant: Event, extra: Partial<Parameters<typeof decodeMemberEpochGrant>[1]> = {}) {
    return decodeMemberEpochGrant(grant, {
      roomId,
      authority,
      deviceSk: requesterDeviceSk,
      requests,
      current: keysOf(E0),
      participant: requester.pubkey,
      now: NOW,
      ...extra,
    })
  }

  it('accepts a member grant whose chain the authority signed and whose last secret matches its commitment', () => {
    const chain = buildChain([{}, { commit: true, removed: [gone.pubkey] }])
    const known = 'cd'.repeat(32)
    const grant = decode(grantFrom(chain, 0), { removed: [known] })
    expect(grant).not.toBeNull()
    expect(grant!.epoch).toEqual(chain.epochs[2])
    expect(grant!.removed).toEqual([gone.pubkey, known].sort())
    expect(grant!.from).toBe(getPublicKey(memberDeviceSk))
    // From epoch 1, the same room needs only the last step.
    const fromOne = decode(grantFrom(chain, 1), { current: keysOf(chain.epochs[1]!) })
    expect(fromOne!.epoch).toEqual(chain.epochs[2])
  })

  it('rejects a forged or mismatched secret, at the top of the chain or in the middle', () => {
    const chain = buildChain([{ commit: true }, { commit: true }])
    const forgedTop = grantFrom(chain, 0, { tamper: (e) => [e[0]!, { epoch: 2, secret: generateEpochSecret() }] })
    expect(decode(forgedTop)).toBeNull()
    const forgedMiddle = grantFrom(chain, 0, { tamper: (e) => [{ epoch: 1, secret: generateEpochSecret() }, e[1]!] })
    expect(decode(forgedMiddle)).toBeNull()
    // A member minting its own "epoch": a rekey it signed itself.
    const fork = encodeRekeyEvent({
      roomId,
      authoritySk: memberDeviceSk,
      current: keysOf(E0),
      next: { epoch: 1, secret: generateEpochSecret() },
      recipients: [],
      removed: [],
      commit: true,
      now: NOW,
    })
    const forked = encodeMemberEpochGrant({
      roomId, deviceSk: memberDeviceSk, device: requesterDevice, request: requestId,
      epochs: [{ epoch: 1, secret: generateEpochSecret() }], rekeys: [fork], now: NOW,
    })
    expect(decode(forked)).toBeNull()
  })

  it('rejects a member grant for a legacy epoch with no commitment: that epoch stays authority-only', () => {
    const legacy = buildChain([{}])
    expect(decode(grantFrom(legacy, 0))).toBeNull()
    // A legacy epoch in the middle is fine: the next rekey vouches for it.
    const mixed = buildChain([{}, { commit: true }])
    expect(decode(grantFrom(mixed, 0))).not.toBeNull()
  })

  it('rejects a chain that removes the requester, or closes the room', () => {
    const removing = buildChain([{ commit: true, removed: [requester.pubkey] }])
    expect(decode(grantFrom(removing, 0))).toBeNull()
    const closing = buildChain([{ commit: true }, { commit: true, closed: true }])
    expect(decode(grantFrom(closing, 0))).toBeNull()
  })

  it('rejects a grant that stops short of a rekey the requester has seen, another request, or another device', () => {
    const chain = buildChain([{ commit: true }, { commit: true }])
    const short = encodeMemberEpochGrant({
      roomId, deviceSk: memberDeviceSk, device: requesterDevice, request: requestId,
      epochs: [chain.epochs[1]!], rekeys: [chain.rekeys[0]!], now: NOW,
    })
    expect(decode(short)).not.toBeNull()
    expect(decode(short, { expected: 2 })).toBeNull()
    expect(decode(grantFrom(chain, 0), { requests: new Set(['ef'.repeat(32)]) })).toBeNull()
    expect(decode(grantFrom(chain, 0), { deviceSk: generateSecretKey() })).toBeNull()
  })
})

describe('the member desk', () => {
  /** A member at the chain's top that holds every secret and rekey. */
  function desk(relay: SimRelay, chain: Chain, extra: Partial<Parameters<typeof hostMemberEpochDesk>[0]> = {}, deviceSk = memberDeviceSk) {
    const top = chain.epochs[chain.epochs.length - 1]!
    return hostMemberEpochDesk({
      transport: new SimTransport(relay),
      roomId,
      authority,
      deviceSk,
      roomKey,
      current: () => top,
      secretAt: (n) => chain.epochs[n]?.secret,
      rekeyAt: (n) => chain.rekeys[n - 1],
      removed: () => new Set([gone.pubkey]),
      jitterMs: 0,
      now,
      ...extra,
    })
  }

  async function ask(relay: SimRelay, opts: { deviceSk?: Uint8Array; id?: ReturnType<typeof localIdentity>; timeoutMs?: number; expected?: number } = {}) {
    const deviceSk = opts.deviceSk ?? requesterDeviceSk
    return requestMemberEpoch({
      transport: new SimTransport(relay),
      roomId,
      authority,
      deviceSk,
      roomKey,
      credential: await credentialFor(deviceSk, opts.id ?? requester),
      current: keysOf(E0),
      expected: opts.expected,
      now,
      timeoutMs: opts.timeoutMs ?? 1_000,
      retryMs: 50,
    })
  }

  it('brings a member that missed two rekeys up to date while the authority is offline', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{ commit: true }, { commit: true, removed: [gone.pubkey] }])
    const granted: MemberEpochRequest[] = []
    const handle = desk(relay, chain, { onGranted: (r) => granted.push(r) })
    const grant = await ask(relay, { expected: 2 })
    expect(grant.epoch).toEqual(chain.epochs[2])
    expect(grant.removed).toEqual([gone.pubkey])
    expect(granted).toHaveLength(1)
    expect(granted[0]!.participant).toBe(requester.pubkey)
    handle.close()
  })

  it('refuses a removed requester by not answering', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{ commit: true, removed: [gone.pubkey] }])
    const refused: string[] = []
    const handle = desk(relay, chain, { onRefused: (_r, why) => refused.push(why) })
    await expect(ask(relay, { deviceSk: goneDeviceSk, id: gone, timeoutMs: 200 })).rejects.toThrow(/no current member/)
    expect(refused[0]).toBe('removed')
    expect(relay.published.filter((e) => e.kind === MEMBER_EPOCH_KINDS.GRANT)).toHaveLength(0)
    handle.close()
  })

  it('refuses everybody once the room is closed', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{ commit: true }])
    const refused: string[] = []
    const handle = desk(relay, chain, { closed: () => true, onRefused: (_r, why) => refused.push(why) })
    await expect(ask(relay, { timeoutMs: 200 })).rejects.toThrow(/no current member/)
    expect(refused[0]).toBe('closed')
    expect(relay.published.filter((e) => e.kind === MEMBER_EPOCH_KINDS.GRANT)).toHaveLength(0)
    handle.close()
  })

  it('stays silent for a legacy epoch it can see has no commitment, leaving it to the authority', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{}])
    const handle = desk(relay, chain)
    await expect(ask(relay, { timeoutMs: 200 })).rejects.toThrow(/no current member/)
    expect(relay.published.filter((e) => e.kind === MEMBER_EPOCH_KINDS.GRANT)).toHaveLength(0)
    handle.close()
  })

  it('does not answer a stranger with the room id and no room key', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{ commit: true }])
    const handle = desk(relay, chain)
    const strangerSk = generateSecretKey()
    const stranger = localIdentity(generateSecretKey())
    const forged = encodeMemberEpochRequest({
      roomId, authority, deviceSk: strangerSk, roomKey: new Uint8Array(32).fill(9),
      credential: await credentialFor(strangerSk, stranger), have: 0, now: NOW,
    })
    await new SimTransport(relay).publish(forged)
    expect(relay.published.filter((e) => e.kind === MEMBER_EPOCH_KINDS.GRANT)).toHaveLength(0)
    handle.close()
  })

  it('with two answerers the first grant that verifies wins, and a forged one ahead of it is ignored', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{ commit: true }])
    // A dishonest member answers first, with a secret of its own.
    const liarSk = generateSecretKey()
    const liarRelayView = new SimTransport(relay)
    const unsubLiar = liarRelayView.subscribe([{ kinds: [MEMBER_EPOCH_KINDS.REQUEST], '#d': [roomId] }], (event) => {
      const request = decodeMemberEpochRequest(event, { roomId, authority, roomKey, now: NOW })
      if (!request) return
      liarRelayView.publish(encodeMemberEpochGrant({
        roomId, deviceSk: liarSk, device: request.device, request: request.request,
        epochs: [{ epoch: 1, secret: generateEpochSecret() }], rekeys: [chain.rekeys[0]!], now: NOW,
      })).catch(() => {})
    })
    const honestSk = generateSecretKey()
    const first = desk(relay, chain, {}, honestSk)
    const second = desk(relay, chain)
    const grant = await ask(relay)
    expect(grant.epoch).toEqual(chain.epochs[1])
    expect(grant.from).toBe(getPublicKey(honestSk))
    unsubLiar()
    first.close()
    second.close()
  })

  it('stands down once when another member answered during its wait, and answers the next request', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{ commit: true }])
    const granted: string[] = []
    const handle = desk(relay, chain, { jitterMs: 40, random: () => 0.99, onGranted: (r) => granted.push(r.request) })
    const transport = new SimTransport(relay)
    const credential = await credentialFor(requesterDeviceSk, requester)
    const r1 = encodeMemberEpochRequest({ roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential, have: 0, now: NOW })
    await transport.publish(r1)
    // Somebody else's grant to the same device lands during the wait. It
    // could be junk: the desk cannot read it, and stands down only once.
    await transport.publish(encodeMemberEpochGrant({
      roomId, deviceSk: generateSecretKey(), device: requesterDevice, request: r1.id,
      epochs: [chain.epochs[1]!], rekeys: [chain.rekeys[0]!], now: NOW,
    }))
    await new Promise((r) => setTimeout(r, 80))
    expect(granted).toEqual([])
    const r2 = encodeMemberEpochRequest({ roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential, have: 0, now: NOW + 1 })
    await transport.publish(r2)
    await transport.publish(encodeMemberEpochGrant({
      roomId, deviceSk: generateSecretKey(), device: requesterDevice, request: r2.id,
      epochs: [chain.epochs[1]!], rekeys: [chain.rekeys[0]!], now: NOW,
    }))
    await new Promise((r) => setTimeout(r, 80))
    expect(granted).toEqual([r2.id])
    handle.close()
  })
})

describe('requestRoomEpoch with members', () => {
  it('settles on a member grant when the authority is offline', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{ commit: true }])
    const memberDesk = hostMemberEpochDesk({
      transport: new SimTransport(relay), roomId, authority, deviceSk: memberDeviceSk, roomKey,
      current: () => chain.epochs[1], rekeyAt: (n) => chain.rekeys[n - 1], removed: () => new Set(), jitterMs: 0, now,
    })
    const credential = await credentialFor(requesterDeviceSk, requester)
    const members = memberEpochSource({
      transport: new SimTransport(relay), roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential,
      current: keysOf(E0), now, retryMs: 50,
    })
    const grant = await requestRoomEpoch({
      transport: new SimTransport(relay), roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential, now, timeoutMs: 1_000, members,
    })
    expect(grant.epoch).toEqual(chain.epochs[1])
    memberDesk.close()
  })

  it('still settles on the authority for a legacy room no member can vouch for', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{}])
    const authorityDesk = hostRoomEpoch({
      transport: new SimTransport(relay), roomId, authoritySk, roomKey, current: () => chain.epochs[1]!, removed: () => new Set(), now,
    })
    const memberDesk = hostMemberEpochDesk({
      transport: new SimTransport(relay), roomId, authority, deviceSk: memberDeviceSk, roomKey,
      current: () => chain.epochs[1], rekeyAt: (n) => chain.rekeys[n - 1], removed: () => new Set(), jitterMs: 0, now,
    })
    const credential = await credentialFor(requesterDeviceSk, requester)
    const members = memberEpochSource({
      transport: new SimTransport(relay), roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential,
      current: keysOf(E0), now, retryMs: 50,
    })
    const grant = await requestRoomEpoch({
      transport: new SimTransport(relay), roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential, now, timeoutMs: 1_000, members,
    })
    expect(grant.epoch).toEqual(chain.epochs[1])
    expect('from' in grant).toBe(false)
    authorityDesk.close()
    memberDesk.close()
  })
})
