import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { base64urlnopad } from '@scure/base'
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

/** Devices and participants: a member device that answers, a requester, and one who is removed. */
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

  it('does not publish a grant larger than its byte budget', async () => {
    const relay = new SimRelay()
    const chain = buildChain([{ commit: true }])
    const handle = desk(relay, chain, { maxGrantBytes: 500 })
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
    const handle = desk(relay, chain, { jitterMs: 20, random: () => 0.99, onGranted: (r) => granted.push(r.request) })
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
    await new Promise((r) => setTimeout(r, 150))
    expect(granted).toEqual([])
    const r2 = encodeMemberEpochRequest({ roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential, have: 0, now: NOW + 1 })
    await transport.publish(r2)
    await transport.publish(encodeMemberEpochGrant({
      roomId, deviceSk: generateSecretKey(), device: requesterDevice, request: r2.id,
      epochs: [chain.epochs[1]!], rekeys: [chain.rekeys[0]!], now: NOW,
    }))
    await new Promise((r) => setTimeout(r, 150))
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

describe('the requester floors a member grant at the newest rekey its relays replay', () => {
  /** Publish the authority's rekeys to the relay, as the authority's client does. */
  async function publishRekeys(relay: SimRelay, chain: Chain) {
    const transport = new SimTransport(relay)
    for (const rekey of chain.rekeys) await transport.publish(rekey)
  }

  async function askWithoutExpected(relay: SimRelay, timeoutMs = 300) {
    return requestMemberEpoch({
      transport: new SimTransport(relay), roomId, authority, deviceSk: requesterDeviceSk, roomKey,
      credential: await credentialFor(requesterDeviceSk, requester), current: keysOf(E0), now, timeoutMs, retryMs: 50,
    })
  }

  it('refuses a stale chain from a member removed at the top, though the caller passed no `expected`', async () => {
    const relay = new SimRelay({ replay: true })
    const chain = buildChain([{ commit: true }, { commit: true }, { commit: true, removed: [gone.pubkey] }])
    await publishRekeys(relay, chain)
    // `gone` was removed at epoch 3: it still holds epoch 2 and every rekey to
    // it, and its own removed set does not name the requester.
    const stale = hostMemberEpochDesk({
      transport: new SimTransport(relay), roomId, authority, deviceSk: goneDeviceSk, roomKey,
      current: () => chain.epochs[2], secretAt: (n) => chain.epochs[n]?.secret, rekeyAt: (n) => chain.rekeys[n - 1],
      removed: () => new Set(), jitterMs: 0, now,
    })
    await expect(askWithoutExpected(relay)).rejects.toThrow(/no current member/)
    expect(relay.published.filter((e) => e.kind === MEMBER_EPOCH_KINDS.GRANT).length).toBeGreaterThan(0)
    stale.close()
  })

  it('still accepts a chain that reaches the newest rekey', async () => {
    const relay = new SimRelay({ replay: true })
    const chain = buildChain([{ commit: true }, { commit: true }])
    await publishRekeys(relay, chain)
    const honest = hostMemberEpochDesk({
      transport: new SimTransport(relay), roomId, authority, deviceSk: memberDeviceSk, roomKey,
      current: () => chain.epochs[2], secretAt: (n) => chain.epochs[n]?.secret, rekeyAt: (n) => chain.rekeys[n - 1],
      removed: () => new Set(), jitterMs: 0, now,
    })
    const grant = await askWithoutExpected(relay, 1_000)
    expect(grant.epoch).toEqual(chain.epochs[2])
    honest.close()
  })

  it('ignores a rekey the authority did not sign, or one for another room, when setting the floor', async () => {
    const relay = new SimRelay({ replay: true })
    const chain = buildChain([{ commit: true }])
    await publishRekeys(relay, chain)
    const transport = new SimTransport(relay)
    // A rekey to epoch 9 signed by somebody else, and a real authority rekey
    // to epoch 9 for a different room: neither may raise the floor.
    await transport.publish(encodeRekeyEvent({
      roomId, authoritySk: generateSecretKey(), current: { epoch: 8, id: '', key: roomKey },
      next: { epoch: 9, secret: generateEpochSecret() }, recipients: [], removed: [], now: NOW,
    }))
    const otherRoom = deriveRoom(new Uint8Array(32).fill(5))
    await transport.publish(encodeRekeyEvent({
      roomId: otherRoom.roomId, authoritySk, current: { epoch: 8, id: '', key: otherRoom.roomKey },
      next: { epoch: 9, secret: generateEpochSecret() }, recipients: [], removed: [], now: NOW,
    }))
    const honest = hostMemberEpochDesk({
      transport: new SimTransport(relay), roomId, authority, deviceSk: memberDeviceSk, roomKey,
      current: () => chain.epochs[1], rekeyAt: (n) => chain.rekeys[n - 1], removed: () => new Set(), jitterMs: 0, now,
    })
    const grant = await askWithoutExpected(relay, 1_000)
    expect(grant.epoch).toEqual(chain.epochs[1])
    honest.close()
  })
})

describe('member epoch refusals the other tests do not reach', () => {
  const requestId = 'ab'.repeat(32)
  const requests = new Set([requestId])
  const memberDevice = getPublicKey(memberDeviceSk)

  function decode(grant: Event, extra: Partial<Parameters<typeof decodeMemberEpochGrant>[1]> = {}) {
    return decodeMemberEpochGrant(grant, {
      roomId, authority, deviceSk: requesterDeviceSk, requests, current: keysOf(E0), participant: requester.pubkey, now: NOW, ...extra,
    })
  }

  /** A grant built by hand, for shapes `encodeMemberEpochGrant` will not make. */
  function rawGrant(body: unknown, tags: string[][] = [['d', roomId], ['p', requesterDevice]], createdAt = NOW): Event {
    return finalizeEvent(
      {
        kind: MEMBER_EPOCH_KINDS.GRANT,
        created_at: createdAt,
        tags,
        content: nip44.v2.encrypt(JSON.stringify(body), nip44.v2.utils.getConversationKey(memberDeviceSk, requesterDevice)),
      },
      memberDeviceSk,
    )
  }

  it('refuses an authority-signed rekey for another room spliced into the chain, even one that decrypts', () => {
    const otherRoom = deriveRoom(new Uint8Array(32).fill(4)).roomId
    const next = { epoch: 1, secret: generateEpochSecret() }
    // The same authority, the same epoch-0 key as this room, another room id.
    const spliced = encodeRekeyEvent({ roomId: otherRoom, authoritySk, current: keysOf(E0), next, recipients: [], removed: [], commit: true, now: NOW })
    const grant = encodeMemberEpochGrant({
      roomId, deviceSk: memberDeviceSk, device: requesterDevice, request: requestId, epochs: [next], rekeys: [spliced], now: NOW,
    })
    expect(decode(grant)).toBeNull()
    // In the middle of a chain, where no commitment is checked, the room tag
    // alone refuses it.
    const top = { epoch: 2, secret: generateEpochSecret() }
    const onTop = encodeRekeyEvent({ roomId, authoritySk, current: deriveEpoch(next), next: top, recipients: [], removed: [], commit: true, now: NOW })
    expect(decode(encodeMemberEpochGrant({
      roomId, deviceSk: memberDeviceSk, device: requesterDevice, request: requestId, epochs: [next, top], rekeys: [spliced, onTop], now: NOW,
    }))).toBeNull()
    // The same splice is accepted in the room the rekey names: the refusal is
    // the room binding, not something else.
    expect(decodeMemberEpochGrant(
      encodeMemberEpochGrant({ roomId: otherRoom, deviceSk: memberDeviceSk, device: requesterDevice, request: requestId, epochs: [next], rekeys: [spliced], now: NOW }),
      { roomId: otherRoom, authority, deviceSk: requesterDeviceSk, requests, current: keysOf(E0), participant: requester.pubkey, now: NOW },
    )).not.toBeNull()
  })

  it('refuses a chain longer than 32 epochs', () => {
    const chain = buildChain(Array.from({ length: 33 }, () => ({ commit: true })))
    const body = {
      v: 1, request: requestId, epoch: 33,
      secrets: chain.epochs.slice(1).map((e) => base64urlnopad.encode(e.secret)),
      rekeys: chain.rekeys,
    }
    expect(decode(rawGrant(body))).toBeNull()
    // One shorter, from epoch 1, is accepted.
    const from1 = { ...body, secrets: body.secrets.slice(1), rekeys: body.rekeys.slice(1) }
    expect(decode(rawGrant(from1), { current: keysOf(chain.epochs[1]!) })).not.toBeNull()
  })

  it('refuses a grant whose `p` names another device, and a stale one', () => {
    const chain = buildChain([{ commit: true }])
    const body = { v: 1, request: requestId, epoch: 1, secrets: [base64urlnopad.encode(chain.epochs[1]!.secret)], rekeys: chain.rekeys }
    expect(decode(rawGrant(body))).not.toBeNull()
    expect(decode(rawGrant(body, [['d', roomId], ['p', memberDevice]]))).toBeNull()
    expect(decode(rawGrant(body, [['d', roomId], ['p', requesterDevice]], NOW - 600))).toBeNull()
  })

  it('a desk re-checks removal and closure after its wait, and answers nothing it learnt of meanwhile', async () => {
    for (const change of ['removed', 'closed'] as const) {
      const relay = new SimRelay()
      const chain = buildChain([{ commit: true }])
      const removed = new Set<string>()
      let closed = false
      const granted: string[] = []
      const handle = hostMemberEpochDesk({
        transport: new SimTransport(relay), roomId, authority, deviceSk: memberDeviceSk, roomKey,
        current: () => chain.epochs[1], rekeyAt: (n) => chain.rekeys[n - 1], removed: () => removed, closed: () => closed,
        jitterMs: 40, random: () => 0.99, now, onGranted: (r) => granted.push(r.request),
      })
      const credential = await credentialFor(requesterDeviceSk, requester)
      await new SimTransport(relay).publish(
        encodeMemberEpochRequest({ roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential, have: 0, now: NOW }),
      )
      if (change === 'removed') removed.add(requester.pubkey)
      else closed = true
      await new Promise((r) => setTimeout(r, 120))
      expect(granted).toEqual([])
      expect(relay.published.filter((e) => e.kind === MEMBER_EPOCH_KINDS.GRANT)).toHaveLength(0)
      handle.close()
    }
  })

  it('a desk leaves a requester more than 32 epochs behind to the authority', async () => {
    const relay = new SimRelay()
    const chain = buildChain(Array.from({ length: 33 }, () => ({ commit: true })))
    const handle = hostMemberEpochDesk({
      transport: new SimTransport(relay), roomId, authority, deviceSk: memberDeviceSk, roomKey,
      current: () => chain.epochs[33], secretAt: (n) => chain.epochs[n]?.secret, rekeyAt: (n) => chain.rekeys[n - 1],
      removed: () => new Set(), jitterMs: 0, now, maxGrantBytes: 10_000_000,
    })
    const credential = await credentialFor(requesterDeviceSk, requester)
    const transport = new SimTransport(relay)
    await transport.publish(encodeMemberEpochRequest({ roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential, have: 0, now: NOW }))
    expect(relay.published.filter((e) => e.kind === MEMBER_EPOCH_KINDS.GRANT)).toHaveLength(0)
    // From epoch 1 the chain is 32 long, and it is answered.
    await transport.publish(encodeMemberEpochRequest({ roomId, authority, deviceSk: requesterDeviceSk, roomKey, credential, have: 1, now: NOW + 1 }))
    expect(relay.published.filter((e) => e.kind === MEMBER_EPOCH_KINDS.GRANT)).toHaveLength(1)
    handle.close()
  })
})

describe('the requester waits for the rekey replay before it asks', () => {
  /** A relay that replays stored rekeys, then EOSE, only after `delayMs`:
   *  what a real relay does over a network. Everything else is immediate. */
  function slowReplay(relay: SimRelay, delayMs: number) {
    const inner = new SimTransport(relay)
    return {
      publish: (event: Event) => inner.publish(event),
      close: () => inner.close(),
      subscribe(filters: Parameters<SimTransport['subscribe']>[0], onEvent: (event: Event) => void, onEose?: () => void) {
        if (!filters.some((f) => f.kinds?.includes(1462))) return inner.subscribe(filters, onEvent, onEose)
        let off = () => {}
        let gone = false
        const timer = setTimeout(() => {
          if (!gone) off = inner.subscribe(filters, onEvent, onEose)
        }, delayMs)
        return () => {
          gone = true
          clearTimeout(timer)
          off()
        }
      },
    }
  }

  it('so a member removed at the top cannot answer faster than the relays replay', async () => {
    const relay = new SimRelay({ replay: true })
    const chain = buildChain([{ commit: true }, { commit: true }, { commit: true, removed: [gone.pubkey] }])
    for (const rekey of chain.rekeys) await new SimTransport(relay).publish(rekey)
    const stale = hostMemberEpochDesk({
      transport: new SimTransport(relay), roomId, authority, deviceSk: goneDeviceSk, roomKey,
      current: () => chain.epochs[2], secretAt: (n) => chain.epochs[n]?.secret, rekeyAt: (n) => chain.rekeys[n - 1],
      removed: () => new Set(), jitterMs: 0, now,
    })
    await expect(requestMemberEpoch({
      transport: slowReplay(relay, 50), roomId, authority, deviceSk: requesterDeviceSk, roomKey,
      credential: await credentialFor(requesterDeviceSk, requester), current: keysOf(E0), now, timeoutMs: 400, retryMs: 50,
    })).rejects.toThrow(/no current member/)
    stale.close()
  })
})
