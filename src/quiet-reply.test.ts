import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure'
import { SimRelay, SimTransport } from '../test/sim-relay.js'
import { createDeviceCredential } from './credential.js'
import { localIdentity } from './identity.js'
import { deriveRoom } from './room.js'
import { KINDS } from './kinds.js'
import {
  decodeEpochGrant,
  encodeEpochRequest,
  generateEpochSecret,
  hostRoomEpoch,
} from './epoch.js'
import {
  createRoomInvitation,
  decodeRoomAdmissionGrant,
  deriveInvitationId,
  encodeInvitationGrant,
  encodeInvitationRequest,
  hostRoomInvitation,
} from './invitation.js'
import {
  DEFAULT_REPLY_DELAY_MS,
  MAX_REFUSALS_PER_MINUTE,
  REFUSAL_LIMITER_CAPACITY,
  REFUSE_AGAIN_AFTER_SECONDS,
  RefusalLimiter,
  replyDelay,
} from './quiet-reply.js'

const NOW = 1_800_000_000
const ROOM_SECRET = new Uint8Array(32).fill(7)
const { roomId, roomKey } = deriveRoom(ROOM_SECRET)

/** A scheduler the test drives: nothing runs until `run` says so. */
function manualSchedule() {
  const queue: Array<{ fn: () => void; ms: number; cancelled: boolean }> = []
  return {
    queue,
    schedule: (fn: () => void, ms: number) => {
      const entry = { fn, ms, cancelled: false }
      queue.push(entry)
      return () => { entry.cancelled = true }
    },
    /** Run everything queued so far, in order. */
    run() {
      for (const entry of queue.splice(0)) if (!entry.cancelled) entry.fn()
    },
  }
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0))

describe('replyDelay', () => {
  it('draws whole milliseconds inside the range, from the random source', () => {
    expect(replyDelay([500, 2000], () => 0)).toBe(500)
    expect(replyDelay([500, 2000], () => 0.5)).toBe(1250)
    expect(replyDelay([500, 2000], () => 0.9999)).toBe(1999)
    expect(replyDelay(DEFAULT_REPLY_DELAY_MS, () => 0)).toBe(500)
  })

  it('reads nonsense safely: no range is no wait, a backwards one is turned round', () => {
    expect(replyDelay([0, 0])).toBe(0)
    expect(replyDelay([2000, 500], () => 0)).toBe(500)
    expect(replyDelay([-10, -1])).toBe(0)
    expect(replyDelay([Number.NaN, 5])).toBe(0)
    expect(replyDelay([100, 200], () => Number.NaN)).toBe(100)
    expect(replyDelay([100, 200], () => 7)).toBe(200)
  })
})

describe('RefusalLimiter', () => {
  it('lets one refusal a key through per window', () => {
    const limiter = new RefusalLimiter()
    expect(limiter.allow('a', 60, NOW)).toBe(true)
    expect(limiter.allow('a', 60, NOW + 59)).toBe(false)
    expect(limiter.allow('b', 60, NOW + 59)).toBe(true)
    expect(limiter.allow('a', 60, NOW + 60)).toBe(true)
    limiter.forget('a')
    expect(limiter.allow('a', 60, NOW + 61)).toBe(true)
  })

  it('caps refusals a minute across every key, and a turned-away key is not recorded', () => {
    const limiter = new RefusalLimiter({ perMinute: 3 })
    expect(['a', 'b', 'c', 'd'].map((k) => limiter.allow(k, 3600, NOW))).toEqual([true, true, true, false])
    expect(limiter.size).toBe(3)
    expect(limiter.allow('d', 3600, NOW + 59)).toBe(false)
    expect(limiter.allow('d', 3600, NOW + 60)).toBe(true)
    // By default, fresh keys - what anyone can mint - get 20 a minute.
    const fresh = new RefusalLimiter()
    const sent = Array.from({ length: 35 }, (_, i) => fresh.allow(`fresh${i}`, 3600, NOW)).filter(Boolean)
    expect(sent).toHaveLength(MAX_REFUSALS_PER_MINUTE)
    expect(MAX_REFUSALS_PER_MINUTE).toBe(20)
  })

  it('remembers a bounded number of keys, forgetting the oldest first', () => {
    const limiter = new RefusalLimiter({ perMinute: Number.MAX_SAFE_INTEGER })
    for (let i = 0; i < 10_000; i += 1) limiter.allow(`k${i}`, 3600, NOW)
    expect(limiter.size).toBe(REFUSAL_LIMITER_CAPACITY)
    // The newest are still held back; the oldest were forgotten.
    expect(limiter.allow('k9999', 3600, NOW)).toBe(false)
    expect(limiter.allow('k0', 3600, NOW)).toBe(true)
    expect(limiter.size).toBe(REFUSAL_LIMITER_CAPACITY)

    const small = new RefusalLimiter({ capacity: 2, perMinute: 100 })
    small.allow('a', 3600, NOW)
    small.allow('b', 3600, NOW)
    small.allow('c', 3600, NOW)
    expect(small.size).toBe(2)
    expect(small.allow('a', 3600, NOW)).toBe(true)
    expect(small.allow('c', 3600, NOW)).toBe(false)
  })
})

describe('the authority desk answers quietly', () => {
  const authoritySk = generateSecretKey()
  const authority = getPublicKey(authoritySk)
  const member = localIdentity(generateSecretKey())
  const gone = localIdentity(generateSecretKey())
  const epoch = { epoch: 2, secret: generateEpochSecret() }

  function setup(extra: Partial<Parameters<typeof hostRoomEpoch>[0]> = {}) {
    const relay = new SimRelay()
    const clock = { t: NOW }
    const timer = manualSchedule()
    const handle = hostRoomEpoch({
      transport: new SimTransport(relay),
      roomId,
      authoritySk,
      roomKey,
      current: () => epoch,
      removed: () => new Set([gone.pubkey]),
      known: (p) => p === member.pubkey,
      now: () => clock.t,
      schedule: timer.schedule,
      random: () => 0.5,
      ...extra,
    })
    /** One fresh request from a fresh device of `who`, as the relay hands it on. */
    const ask = async (who: ReturnType<typeof localIdentity>) => {
      const deviceSk = generateSecretKey()
      const credential = await createDeviceCredential({
        identity: who, devicePubkey: getPublicKey(deviceSk), roomId, expiresAt: NOW + 86_400, now: () => clock.t,
      })
      const request = encodeEpochRequest({ roomId, authority, deviceSk, roomKey, credential, now: clock.t })
      relay.publish(request)
      return { deviceSk, request }
    }
    const grants = () => relay.published.filter((e) => e.kind === KINDS.EPOCH_GRANT)
    return { relay, clock, timer, handle, ask, grants }
  }

  it('waits a random 0.5 to 2 seconds before a grant, and publishes nothing before then', async () => {
    const { timer, handle, ask, grants, clock } = setup()
    const { deviceSk, request } = await ask(member)
    expect(grants()).toHaveLength(0)
    expect(timer.queue.map((e) => e.ms)).toEqual([1250])
    timer.run()
    expect(grants()).toHaveLength(1)
    expect(decodeEpochGrant(grants()[0]!, { roomId, authority, deviceSk, request: request.id, now: clock.t })).toMatchObject({ epoch })
    handle.close()
  })

  it('does not queue a retry of a request already waiting', async () => {
    const { relay, timer, handle, ask, grants } = setup()
    const { request } = await ask(member)
    relay.publish(request)
    relay.publish(request)
    expect(timer.queue).toHaveLength(1)
    timer.run()
    expect(grants()).toHaveLength(1)
    handle.close()
  })

  it('delays refusals as well as grants', async () => {
    const { timer, handle, ask, grants } = setup()
    await ask(gone)
    expect(grants()).toHaveLength(0)
    expect(timer.queue).toHaveLength(1)
    timer.run()
    expect(grants()).toHaveLength(1)
    handle.close()
  })

  it('closing during the wait publishes nothing', async () => {
    const { timer, handle, ask, grants } = setup()
    await ask(member)
    await ask(gone)
    handle.close()
    expect(timer.queue.every((e) => e.cancelled)).toBe(true)
    // Even a scheduler that ignores the cancel cannot make it answer.
    for (const entry of timer.queue) entry.fn()
    expect(grants()).toHaveLength(0)
  })

  it('[0, 0] answers at once, without the scheduler', async () => {
    const { timer, handle, ask, grants } = setup({ replyDelayMs: [0, 0] })
    await ask(member)
    expect(timer.queue).toHaveLength(0)
    expect(grants()).toHaveLength(1)
    handle.close()
  })

  it('refuses a removed participant asking afresh once an hour, not once a request', async () => {
    const refusedAtDesk: string[] = []
    const { timer, handle, ask, grants, clock } = setup({ onRefused: (_, why) => refusedAtDesk.push(why) })
    const first = await ask(gone)
    timer.run()
    expect(grants()).toHaveLength(1)
    expect(decodeEpochGrant(grants()[0]!, { roomId, authority, deviceSk: first.deviceSk, request: first.request.id, now: clock.t })).toEqual({ refused: 'removed' })
    for (let i = 0; i < 10; i += 1) {
      clock.t += 60
      await ask(gone)
      timer.run()
    }
    expect(grants()).toHaveLength(1)
    // The desk's own callback still hears every refusal.
    expect(refusedAtDesk).toHaveLength(11)
    clock.t = NOW + REFUSE_AGAIN_AFTER_SECONDS
    await ask(gone)
    timer.run()
    expect(grants()).toHaveLength(2)
    handle.close()
  })

  it('takes the refusal window from `refuseAgainAfter`, and rations `closed` the same way', async () => {
    const { timer, handle, ask, grants, clock } = setup({ refuseAgainAfter: 600, closed: () => true })
    await ask(member)
    await ask(member)
    timer.run()
    expect(grants()).toHaveLength(1)
    clock.t += 600
    await ask(member)
    timer.run()
    expect(grants()).toHaveLength(2)
    handle.close()
  })

  it('answers an unknown participant asking afresh once a minute', async () => {
    const reported: string[] = []
    const { timer, handle, ask, grants, clock } = setup({ onUnknown: (r) => reported.push(r.participant) })
    const stranger = localIdentity(generateSecretKey())
    for (let i = 0; i < 5; i += 1) {
      await ask(stranger)
      timer.run()
      clock.t += 10
    }
    expect(grants()).toHaveLength(1)
    expect(reported).toEqual([stranger.pubkey])
    clock.t = NOW + 60
    await ask(stranger)
    timer.run()
    expect(grants()).toHaveLength(2)
    expect(reported).toEqual([stranger.pubkey, stranger.pubkey])
    handle.close()
  })

  it('caps refusals a minute across fresh participant keys, and never limits a grant', async () => {
    const { timer, handle, ask, grants, clock } = setup({ maxRefusalsPerMinute: 3 })
    for (let i = 0; i < 6; i += 1) await ask(localIdentity(generateSecretKey()))
    timer.run()
    expect(grants()).toHaveLength(3)
    for (let i = 0; i < 6; i += 1) await ask(member)
    timer.run()
    expect(grants()).toHaveLength(9)
    clock.t += 60
    await ask(localIdentity(generateSecretKey()))
    timer.run()
    expect(grants()).toHaveLength(10)
    handle.close()
  })
})

describe('coordinated automatic invitation answering', () => {
  const roomSecret = new Uint8Array(32).fill(74)
  const now = () => NOW

  /** The root responder plus one delegated device, both able to answer. */
  function room() {
    const root = createRoomInvitation()
    const delegateSk = generateSecretKey()
    const seed = finalizeEvent({ kind: 1, created_at: NOW, tags: [], content: '' }, generateSecretKey())
    const handover = encodeInvitationGrant({
      invitation: root.invitation, inviterSk: root.inviterSk, requester: getPublicKey(delegateSk), request: seed.id, roomSecret, now: NOW,
    })
    const admission = decodeRoomAdmissionGrant(handover, { invitation: root.invitation, requesterSk: delegateSk, request: seed.id, now: NOW })!
    return { root, delegateSk, chain: admission.delegate.chain }
  }

  function request(relay: SimRelay, invitation: ReturnType<typeof createRoomInvitation>['invitation']): Event {
    const event = encodeInvitationRequest({ invitation, requesterSk: generateSecretKey(), now: NOW })
    relay.publish(event)
    return event
  }

  const grantsIn = (relay: SimRelay) => relay.published.filter((e) => e.kind === KINDS.INVITATION_GRANT)

  it('without the new options nothing waits and no grant subscription opens', async () => {
    const relay = new SimRelay()
    const { root } = room()
    const timer = manualSchedule()
    let subscriptions = 0
    const base = new SimTransport(relay)
    const transport = {
      publish: (e: Event) => base.publish(e),
      subscribe: (...args: Parameters<SimTransport['subscribe']>) => { subscriptions += 1; return base.subscribe(...args) },
      close: () => base.close(),
    }
    const handle = hostRoomInvitation({ transport, invitation: root.invitation, inviterSk: root.inviterSk, roomSecret, now, schedule: timer.schedule })
    expect(subscriptions).toBe(2)
    request(relay, root.invitation)
    await flush()
    expect(timer.queue).toHaveLength(0)
    expect(grantsIn(relay)).toHaveLength(1)
    handle.close()
  })

  it('`grantDelayMs` waits before every automatic grant', async () => {
    const relay = new SimRelay()
    const { root } = room()
    const timer = manualSchedule()
    const handle = hostRoomInvitation({
      transport: new SimTransport(relay), invitation: root.invitation, inviterSk: root.inviterSk, roomSecret, now,
      grantDelayMs: [500, 2000], random: () => 0, schedule: timer.schedule,
    })
    request(relay, root.invitation)
    await flush()
    expect(grantsIn(relay)).toHaveLength(0)
    expect(timer.queue.map((e) => e.ms)).toEqual([500])
    timer.run()
    await flush()
    expect(grantsIn(relay)).toHaveLength(1)
    handle.close()
  })

  it('the wait comes after an `admit` that says yes', async () => {
    const relay = new SimRelay()
    const { root } = room()
    const timer = manualSchedule()
    const handle = hostRoomInvitation({
      transport: new SimTransport(relay), invitation: root.invitation, inviterSk: root.inviterSk, roomSecret, now,
      admit: async () => true, grantDelayMs: [500, 2000], random: () => 0.5, schedule: timer.schedule,
    })
    request(relay, root.invitation)
    await flush()
    expect(timer.queue.map((e) => e.ms)).toEqual([1250])
    timer.run()
    await flush()
    expect(grantsIn(relay)).toHaveLength(1)
    handle.close()
  })

  it('two coordinated devices: the first to finish waiting answers, the other stands down', async () => {
    const relay = new SimRelay()
    const { root, delegateSk, chain } = room()
    const rootTimer = manualSchedule()
    const memberTimer = manualSchedule()
    const admitted: string[] = []
    const creator = hostRoomInvitation({
      transport: new SimTransport(relay), invitation: root.invitation, inviterSk: root.inviterSk, roomSecret, now,
      coordinate: true, random: () => 0.1, schedule: rootTimer.schedule, onAdmitted: () => admitted.push('root'),
    })
    const member = hostRoomInvitation({
      transport: new SimTransport(relay), invitation: root.invitation, inviterSk: delegateSk, delegation: chain, roomSecret, now,
      coordinate: true, random: () => 0.9, schedule: memberTimer.schedule, onAdmitted: () => admitted.push('member'),
    })
    request(relay, root.invitation)
    await flush()
    expect(rootTimer.queue.map((e) => e.ms)).toEqual([650])
    expect(memberTimer.queue.map((e) => e.ms)).toEqual([1850])
    rootTimer.run()
    await flush()
    memberTimer.run()
    await flush()
    expect(grantsIn(relay)).toHaveLength(1)
    expect(admitted).toEqual(['root'])
    creator.close()
    member.close()
  })

  it('a false grant during the wait costs one round: the retry is answered', async () => {
    const relay = new SimRelay()
    const { root } = room()
    const timer = manualSchedule()
    let asked = 0
    const handle = hostRoomInvitation({
      transport: new SimTransport(relay), invitation: root.invitation, inviterSk: root.inviterSk, roomSecret, now,
      coordinate: true, random: () => 0, schedule: timer.schedule, admit: () => { asked += 1; return true },
    })
    const ask = request(relay, root.invitation)
    await flush()
    // Anyone with the link can name the rendezvous and the requester.
    relay.publish(finalizeEvent({
      kind: KINDS.INVITATION_GRANT, created_at: NOW,
      tags: [['d', deriveInvitationId(root.invitation)], ['p', ask.pubkey]], content: 'junk',
    }, generateSecretKey()))
    timer.run()
    await flush()
    expect(grantsIn(relay).filter((e) => e.content !== 'junk')).toHaveLength(0)
    // The requester's retry of the same request. Approval is not asked again.
    relay.publish(ask)
    await flush()
    relay.publish(finalizeEvent({
      kind: KINDS.INVITATION_GRANT, created_at: NOW,
      tags: [['d', deriveInvitationId(root.invitation)], ['p', ask.pubkey]], content: 'junk',
    }, generateSecretKey()))
    timer.run()
    await flush()
    expect(grantsIn(relay).filter((e) => e.content !== 'junk')).toHaveLength(1)
    expect(asked).toBe(1)
    handle.close()
  })

  it('its own grant does not make a responder stand down, and closing cancels the wait', async () => {
    const relay = new SimRelay()
    const { root } = room()
    const timer = manualSchedule()
    const handle = hostRoomInvitation({
      transport: new SimTransport(relay), invitation: root.invitation, inviterSk: root.inviterSk, roomSecret, now,
      coordinate: true, schedule: timer.schedule,
    })
    // Two requests from one device: the grant to the first is this
    // responder's own, and must not silence the second.
    const requesterSk = generateSecretKey()
    for (const at of [NOW, NOW + 1, NOW + 2]) relay.publish(encodeInvitationRequest({ invitation: root.invitation, requesterSk, now: at }))
    await flush()
    expect(timer.queue).toHaveLength(3)
    timer.queue[0]!.fn()
    await flush()
    timer.queue[1]!.fn()
    await flush()
    expect(grantsIn(relay)).toHaveLength(2)
    handle.close()
    expect(timer.queue[2]!.cancelled).toBe(true)
    timer.queue[2]!.fn()
    await flush()
    expect(grantsIn(relay)).toHaveLength(2)
  })
})
