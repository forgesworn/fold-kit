import { afterEach, describe, expect, it, vi } from 'vitest'
import { generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure'
import { SimRelay, SimTransport } from '../test/sim-relay.js'
import { KINDS } from './kinds.js'
import type { RelayTransport } from './transport.js'
import {
  createRoomInvitation, decodeRoomAdmissionGrant, encodeInvitationGrant,
  encodeInvitationRequest, encodeInvitationRetirement, hostRoomInvitation,
  requestRoomAdmissionCapability, type HostRoomInvitationOptions,
} from './invitation.js'

const NOW = 1_800_000_000
// Drain the bounded promise chain without advancing a request's retry clock.
async function flush(): Promise<void> { for (let i = 0; i < 30; i++) await Promise.resolve() }
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
function setup(options: Partial<HostRoomInvitationOptions> = {}, publish?: (event: Event) => Promise<void>) {
  const relay = new SimRelay(), base = new SimTransport(relay), host = createRoomInvitation()
  const requesterSk = generateSecretKey(), roomSecret = new Uint8Array(32).fill(73)
  const request = encodeInvitationRequest({ invitation: host.invitation, requesterSk, now: NOW })
  const attempts: Event[] = [], admitted = vi.fn(), published = vi.fn(), failed = vi.fn(), admit = vi.fn(() => true)
  const transport: RelayTransport = {
    publish: event => { attempts.push(event); return publish ? publish(event) : base.publish(event) },
    subscribe: (...args) => base.subscribe(...args), close: () => base.close(),
  }
  const serving = hostRoomInvitation({ transport, invitation: host.invitation, inviterSk: host.inviterSk,
    roomSecret, now: () => NOW, admit, onAdmitted: admitted, onGrantPublished: published, onGrantFailed: failed, ...options })
  return { relay, base, host, request, requesterSk, roomSecret, attempts, admitted, published, failed, admit, serving }
}
afterEach(() => vi.useRealTimers())

describe('invitation grant retries', () => {
  it('recovers when the first ephemeral grant precedes the guest subscription', async () => {
    vi.useFakeTimers()
    const relay = new SimRelay(), base = new SimTransport(relay), host = createRoomInvitation()
    const roomSecret = new Uint8Array(32).fill(73), attempts: Event[] = []
    let activate = () => {}
    const guest: RelayTransport = {
      publish: event => base.publish(event), close: () => {},
      subscribe: (...args) => {
        let off = () => {}, closed = false
        activate = () => { if (!closed) off = base.subscribe(...args) }
        return () => { closed = true; off() }
      },
    }
    const admitted = vi.fn(), published = vi.fn(), admit = vi.fn(() => true)
    const serving = hostRoomInvitation({
      invitation: host.invitation, inviterSk: host.inviterSk, roomSecret, now: () => NOW,
      admit, onAdmitted: admitted, onGrantPublished: published,
      transport: { subscribe: (...args) => base.subscribe(...args), close: () => {}, publish: async event => {
        attempts.push(event)
        await base.publish(event) // A real ephemeral relay does not retain this.
        if (attempts.length === 1) activate()
      } },
    })
    const cancel = new AbortController()
    const result = requestRoomAdmissionCapability({ invitation: host.invitation, transport: guest,
      now: () => NOW, retryMs: 2000, timeoutMs: 9000, signal: cancel.signal })
    let joined = false
    void result.then(() => { joined = true }, () => {})
    try {
      await flush()
      expect(attempts).toHaveLength(1)
      expect(joined).toBe(false)
      await vi.advanceTimersByTimeAsync(2000)
      expect(joined).toBe(true)
      expect((await result).secret).toEqual(roomSecret)
      expect(attempts).toHaveLength(2)
      expect(attempts[1]).toBe(attempts[0])
      expect(JSON.stringify(attempts[1])).toBe(JSON.stringify(attempts[0]))
      expect(admit).toHaveBeenCalledTimes(1)
      expect(admitted).toHaveBeenCalledTimes(1)
      expect(published).toHaveBeenCalledTimes(1)
    } finally { cancel.abort(); serving.close() }
  })

  it('coalesces duplicates during approval and publication and acknowledges once', async () => {
    const approval = deferred<boolean>(), send = deferred<void>(), admit = vi.fn(() => approval.promise)
    const s = setup({ admit }, () => send.promise)
    try {
      for (let i = 0; i < 3; i++) s.relay.publish(s.request)
      await flush()
      expect(admit).toHaveBeenCalledTimes(1)
      expect(s.attempts).toHaveLength(0)
      approval.resolve(true); await flush()
      for (let i = 0; i < 3; i++) s.relay.publish(s.request)
      await flush()
      expect(s.attempts).toHaveLength(1)
      expect(s.admitted).not.toHaveBeenCalled()
      send.resolve(); await flush()
      s.relay.publish(s.request); await flush()
      expect(s.attempts).toHaveLength(2)
      expect(s.attempts[1]).toBe(s.attempts[0])
      expect(s.admitted).toHaveBeenCalledTimes(1)
      expect(s.published).toHaveBeenCalledTimes(1)
    } finally { s.serving.close() }
  })

  for (const synchronous of [false, true]) {
    it(`retries the exact signed grant after a ${synchronous ? 'throw' : 'rejection'}`, async () => {
      const error = new Error('first send failed')
      let calls = 0
      const s = setup({}, () => {
        if (++calls > 1) return Promise.resolve()
        if (synchronous) throw error
        return Promise.reject(error)
      })
      try {
        s.relay.publish(s.request); await flush()
        expect(s.failed).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ request: s.request.id }), error)
        expect(s.admitted).not.toHaveBeenCalled()
        s.relay.publish(s.request); await flush()
        expect(s.attempts).toHaveLength(2)
        expect(s.attempts[1]).toBe(s.attempts[0])
        expect(s.admit).toHaveBeenCalledTimes(1)
        expect(s.admitted).toHaveBeenCalledTimes(1)
        expect(s.published).toHaveBeenCalledTimes(1)
      } finally { s.serving.close() }
    })
  }

  for (const decision of ['decline', 'throw'] as const) {
    it(`does not re-prompt a cached ${decision}`, async () => {
      const admit = vi.fn(() => { if (decision === 'throw') throw new Error('decision failed'); return false })
      const s = setup({ admit })
      try {
        s.relay.publish(s.request); await flush()
        s.relay.publish(s.request); await flush()
        expect(admit).toHaveBeenCalledTimes(1)
        expect(s.attempts).toHaveLength(0)
      } finally { s.serving.close() }
    })
  }

  it('retains approval and coalesces duplicates while every send waits its quiet delay', async () => {
    const queue: Array<() => void> = []
    const schedule = vi.fn((fn: () => void) => { queue.push(fn); return () => {} })
    const s = setup({ grantDelayMs: [10, 10], schedule })
    try {
      s.relay.publish(s.request); await flush()
      s.relay.publish(s.request); await flush()
      expect(schedule).toHaveBeenCalledTimes(1)
      expect(s.attempts).toHaveLength(0)
      queue.shift()!(); await flush()
      s.relay.publish(s.request); await flush()
      expect(schedule).toHaveBeenCalledTimes(2)
      expect(s.attempts).toHaveLength(1)
      queue.shift()!(); await flush()
      expect(s.attempts).toHaveLength(2)
      expect(s.attempts[1]).toBe(s.attempts[0])
      expect(s.admit).toHaveBeenCalledTimes(1)
      expect(s.admitted).toHaveBeenCalledTimes(1)
    } finally { s.serving.close() }
  })

  it('supports a scheduler that completes synchronously', async () => {
    const s = setup({ grantDelayMs: [1, 1], schedule: fn => { fn(); return () => {} } })
    try {
      s.relay.publish(s.request); await flush()
      s.relay.publish(s.request); await flush()
      expect(s.attempts).toHaveLength(2)
      expect(s.attempts[1]).toBe(s.attempts[0])
      expect(s.admit).toHaveBeenCalledTimes(1)
    } finally { s.serving.close() }
  })

  for (const boundary of ['expired', 'closed', 'retired'] as const) {
    it(`refuses cached retry after the request is ${boundary}`, async () => {
      let at = NOW
      const s = setup({ now: () => at })
      try {
        s.relay.publish(s.request); await flush()
        expect(s.attempts).toHaveLength(1)
        if (boundary === 'expired') at += 91
        if (boundary === 'closed') s.serving.close()
        if (boundary === 'retired') s.relay.publish(encodeInvitationRetirement({ invitation: s.host.invitation, inviterSk: s.host.inviterSk, now: NOW }))
        s.relay.publish(s.request); await flush()
        expect(s.attempts).toHaveLength(1)
        expect(s.admitted).toHaveBeenCalledTimes(1)
      } finally { s.serving.close() }
    })
  }

  for (const phase of ['approval', 'wait', 'publication'] as const) {
    it(`closing during ${phase} blocks late publication or acknowledgement`, async () => {
      const approval = deferred<boolean>(), send = deferred<void>(), queue: Array<() => void> = []
      const cancel = vi.fn()
      const s = setup({ ...(phase === 'approval' ? { admit: () => approval.promise } : {}),
        ...(phase === 'wait' ? { grantDelayMs: [1, 1] as const, schedule: (fn: () => void) => { queue.push(fn); return cancel } } : {}) },
      phase === 'publication' ? () => send.promise : undefined)
      s.relay.publish(s.request); await flush()
      s.serving.close()
      approval.resolve(true); send.resolve(); queue.forEach(fn => fn()); await flush()
      expect(s.attempts).toHaveLength(phase === 'publication' ? 1 : 0)
      expect(s.admitted).not.toHaveBeenCalled()
      expect(s.published).not.toHaveBeenCalled()
      if (phase === 'wait') expect(cancel).toHaveBeenCalledTimes(1)
    })
  }

  it('refuses a cached retry when the responder delegation has expired', async () => {
    const relay = new SimRelay(), base = new SimTransport(relay), root = createRoomInvitation()
    const delegateSk = generateSecretKey(), roomSecret = new Uint8Array(32).fill(73)
    const seed = encodeInvitationRequest({ invitation: root.invitation, requesterSk: delegateSk, now: NOW })
    const grant = encodeInvitationGrant({ invitation: root.invitation, inviterSk: root.inviterSk, roomSecret,
      requester: getPublicKey(delegateSk), request: seed.id, now: NOW, delegationTtlSeconds: 1 })
    const admission = decodeRoomAdmissionGrant(grant, { invitation: root.invitation, requesterSk: delegateSk, request: seed.id, now: NOW })!
    let at = NOW
    const published = vi.fn(), admit = vi.fn(() => true)
    const serving = hostRoomInvitation({ transport: base, invitation: root.invitation, inviterSk: delegateSk,
      roomSecret, delegation: admission.delegate.chain, now: () => at, admit, onGrantPublished: published })
    try {
      const request = encodeInvitationRequest({ invitation: root.invitation, requesterSk: generateSecretKey(), now: NOW })
      relay.publish(request); await flush()
      at += 2
      relay.publish(request); await flush()
      expect(relay.published.filter(e => e.kind === KINDS.INVITATION_GRANT)).toHaveLength(1)
      expect(published).toHaveBeenCalledTimes(1)
      expect(admit).toHaveBeenCalledTimes(1)
    } finally { serving.close() }
  })

  it('does not reuse a cached grant for another request, invitation or requester', async () => {
    const s = setup()
    try {
      s.relay.publish(s.request); await flush()
      const grant = s.attempts[0]!
      expect(decodeRoomAdmissionGrant(grant, { invitation: s.host.invitation, requesterSk: s.requesterSk, request: s.request.id, now: NOW })).not.toBeNull()
      expect(decodeRoomAdmissionGrant(grant, { invitation: s.host.invitation, requesterSk: s.requesterSk, request: 'f'.repeat(64), now: NOW })).toBeNull()
      expect(decodeRoomAdmissionGrant(grant, { invitation: createRoomInvitation().invitation, requesterSk: s.requesterSk, request: s.request.id, now: NOW })).toBeNull()
      expect(decodeRoomAdmissionGrant(grant, { invitation: s.host.invitation, requesterSk: generateSecretKey(), request: s.request.id, now: NOW })).toBeNull()
    } finally { s.serving.close() }
  })

  it('fails closed at 256 live requests without evicting a pending decision', async () => {
    let at = NOW
    const approval = deferred<boolean>(), admit = vi.fn(() => approval.promise)
    const s = setup({ admit, now: () => at })
    try {
      const requesterSk = generateSecretKey()
      const requests = Array.from({ length: 257 }, (_, i) => encodeInvitationRequest({ invitation: s.host.invitation, requesterSk, now: NOW, name: `Guest ${i}` }))
      for (const request of requests) s.relay.publish(request)
      await flush()
      expect(admit).toHaveBeenCalledTimes(256)
      s.relay.publish(requests[0]!); await flush()
      expect(admit).toHaveBeenCalledTimes(256)
      expect(s.attempts).toHaveLength(0)
      at += 91
      const fresh = encodeInvitationRequest({ invitation: s.host.invitation, requesterSk, now: at })
      s.relay.publish(fresh); await flush()
      // Expiry cannot evict an unresolved decision to admit somebody else.
      expect(admit).toHaveBeenCalledTimes(256)
      approval.resolve(false); await flush()
      s.relay.publish(fresh); await flush()
      expect(admit).toHaveBeenCalledTimes(257)
      expect(s.attempts).toHaveLength(0)
    } finally { s.serving.close() }
  })
})
