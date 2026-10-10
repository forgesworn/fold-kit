import { afterEach, describe, expect, it, vi } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/pure'
import { SimRelay, SimTransport } from '../test/sim-relay.js'
import { localIdentity } from './identity.js'
import type { ParticipantIdentity } from './identity.js'
import type { RelayTransport } from './transport.js'
import type { InvitationRequest } from './invitation.js'
import {
  createRoomInvitation, decodeInvitationRequest, encodeInvitationGrant,
  encodeInvitationRequest, encodeInvitationRetirement, hostRoomInvitation,
  requestRoomAdmissionCapability,
} from './invitation.js'

const NOW = 1_800_000_000
const roomSecret = new Uint8Array(32).fill(44)
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve() }
function deferredIdentity() {
  const account = localIdentity(generateSecretKey())
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  const signEvent = vi.fn(async (event: Parameters<ParticipantIdentity['signEvent']>[0]) => {
    await gate
    return account.signEvent(event)
  })
  return { identity: { pubkey: account.pubkey, signEvent }, release }
}

afterEach(() => vi.useRealTimers())

describe('account proof admission lifecycle', () => {
  it('automatically admits only a proved invited account, retaining caller key ownership', async () => {
    const host = createRoomInvitation(), relay = new SimRelay(), transport = new SimTransport(relay)
    const identity = localIdentity(generateSecretKey()), requesterSk = generateSecretKey(), retainedKey = requesterSk.slice()
    const admitted = vi.fn((request: InvitationRequest) => request.verifiedParticipant === identity.pubkey)
    const desk = hostRoomInvitation({ transport, ...host, roomSecret, now: () => NOW, admit: admitted })
    try {
      const admission = await requestRoomAdmissionCapability({ transport, invitation: host.invitation, identity, requesterSk, now: () => NOW })
      expect(admission.secret).toEqual(roomSecret)
      expect(admission.delegate.delegateSk).toEqual(retainedKey)
      expect(getPublicKey(admission.delegate.delegateSk)).toBe(getPublicKey(retainedKey))
      expect(admitted).toHaveBeenCalledWith(expect.objectContaining({ participant: identity.pubkey, verifiedParticipant: identity.pubkey, device: getPublicKey(requesterSk) }))
      expect(requesterSk).toEqual(retainedKey)
    } finally { desk.close(); relay.close() }
  })

  it('does not automatically admit a bearer holder claiming the invited account', async () => {
    vi.useFakeTimers()
    const host = createRoomInvitation(), relay = new SimRelay(), transport = new SimTransport(relay)
    const invited = getPublicKey(generateSecretKey()), admit = vi.fn((request: InvitationRequest) => request.verifiedParticipant === invited)
    const desk = hostRoomInvitation({ transport, ...host, roomSecret, now: () => NOW, admit })
    const join = requestRoomAdmissionCapability({ transport, invitation: host.invitation, participant: invited, now: () => NOW, timeoutMs: 100 })
    const rejected = expect(join).rejects.toThrow('not answering')
    await flush()
    expect(admit).toHaveBeenCalledWith(expect.objectContaining({ participant: invited }))
    expect(admit.mock.calls[0][0].verifiedParticipant).toBeUndefined()
    expect(relay.published.some(event => event.kind === 20467)).toBe(false)
    await vi.advanceTimersByTimeAsync(100)
    await rejected
    desk.close(); relay.close()
  })

  it('rejects a mismatched account before requesting a signature or subscribing', async () => {
    const host = createRoomInvitation(), { identity } = deferredIdentity()
    const transport = { publish: vi.fn(), subscribe: vi.fn(), close: vi.fn() } as RelayTransport
    await expect(requestRoomAdmissionCapability({ transport, invitation: host.invitation, identity, participant: getPublicKey(generateSecretKey()), now: () => NOW })).rejects.toThrow('does not match')
    expect(identity.signEvent).not.toHaveBeenCalled()
    expect(transport.subscribe).not.toHaveBeenCalled()
  })

  it('waits for a matching proof and clones the request key before asynchronous signing', async () => {
    const host = createRoomInvitation(), relay = new SimRelay(), transport = new SimTransport(relay), { identity, release } = deferredIdentity()
    const requesterSk = generateSecretKey(), originalDevice = getPublicKey(requesterSk), controller = new AbortController()
    const join = requestRoomAdmissionCapability({ transport, invitation: host.invitation, identity, requesterSk, now: () => NOW, signal: controller.signal })
    const rejected = expect(join).rejects.toMatchObject({ name: 'AbortError' })
    expect(relay.published).toHaveLength(0)
    requesterSk.fill(7)
    release(); await flush()
    expect(relay.published).toHaveLength(1)
    expect(decodeInvitationRequest(relay.published[0], { invitation: host.invitation, now: NOW })).toMatchObject({ device: originalDevice, verifiedParticipant: identity.pubkey })
    controller.abort(); await rejected
    expect(requesterSk).toEqual(new Uint8Array(32).fill(7))
    relay.close()
  })

  it.each(['cancel', 'timeout', 'retirement'] as const)('cannot publish a late proof after %s while the signer is waiting', async reason => {
    vi.useFakeTimers()
    const host = createRoomInvitation(), relay = new SimRelay(), underlying = new SimTransport(relay), { identity, release } = deferredIdentity()
    const off = vi.fn(), controller = new AbortController()
    const transport: RelayTransport = { publish: event => underlying.publish(event), close: () => underlying.close(), subscribe: (filters, callback) => {
      const unsub = underlying.subscribe(filters, callback)
      return () => { off(); unsub() }
    } }
    const join = requestRoomAdmissionCapability({ transport, invitation: host.invitation, identity, now: () => NOW, timeoutMs: 100, signal: controller.signal })
    const rejected = expect(join).rejects.toThrow(reason === 'cancel' ? 'cancelled' : reason === 'timeout' ? 'did not finish signing' : 'retired')
    if (reason === 'cancel') controller.abort()
    if (reason === 'timeout') await vi.advanceTimersByTimeAsync(100)
    if (reason === 'retirement') await transport.publish(encodeInvitationRetirement({ ...host, now: NOW }))
    await rejected
    release(); await flush(); await vi.advanceTimersByTimeAsync(10_000)
    expect(off).toHaveBeenCalledTimes(1)
    expect(relay.published.filter(event => event.kind === 20466)).toHaveLength(0)
    relay.close()
  })

  it('handles a synchronous retired invitation replay before invoking the signer', async () => {
    const host = createRoomInvitation(), { identity } = deferredIdentity(), off = vi.fn()
    const transport: RelayTransport = { publish: vi.fn(), close: vi.fn(), subscribe: (_filters, callback) => {
      callback(encodeInvitationRetirement({ ...host, now: NOW }))
      return off
    } }
    await expect(requestRoomAdmissionCapability({ transport, invitation: host.invitation, identity, now: () => NOW })).rejects.toThrow('retired')
    expect(identity.signEvent).not.toHaveBeenCalled()
    expect(off).toHaveBeenCalledTimes(1)
  })

  it('refuses a proof which finishes after its authenticated request time expires', async () => {
    const host = createRoomInvitation(), relay = new SimRelay(), transport = new SimTransport(relay), { identity, release } = deferredIdentity()
    let time = NOW
    const join = requestRoomAdmissionCapability({ transport, invitation: host.invitation, identity, now: () => time })
    const rejected = expect(join).rejects.toThrow('expired while signing')
    time += 91; release(); await rejected
    expect(relay.published).toHaveLength(0)
    relay.close()
  })

  it('shares the request freshness deadline between signing and relay waiting', async () => {
    vi.useFakeTimers()
    const host = createRoomInvitation(), relay = new SimRelay(), transport = new SimTransport(relay), { identity, release } = deferredIdentity()
    const join = requestRoomAdmissionCapability({ transport, invitation: host.invitation, identity, now: () => NOW, timeoutMs: 120_000 })
    const rejected = expect(join).rejects.toThrow('not answering')
    await vi.advanceTimersByTimeAsync(80_000)
    release(); await flush()
    expect(relay.published).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(10_000)
    await rejected
    expect(vi.getTimerCount()).toBe(0)
    relay.close()
  })

  it('cannot issue a grant when a human approves an expired request', async () => {
    const host = createRoomInvitation(), relay = new SimRelay(), transport = new SimTransport(relay)
    let approve!: (yes: boolean) => void, time = NOW
    const onGrantFailed = vi.fn(), onGrantPublished = vi.fn()
    const desk = hostRoomInvitation({ transport, ...host, roomSecret, now: () => time, admit: () => new Promise(resolve => { approve = resolve }), onGrantFailed, onGrantPublished })
    await transport.publish(encodeInvitationRequest({ invitation: host.invitation, requesterSk: generateSecretKey(), now: NOW }))
    await flush(); time += 91; approve(true); await flush()
    expect(onGrantFailed).toHaveBeenCalledWith(expect.any(Object), expect.objectContaining({ message: 'the invitation request expired before admission' }))
    expect(onGrantPublished).not.toHaveBeenCalled()
    expect(relay.published).toHaveLength(1)
    desk.close(); relay.close()
  })

  it('ignores late grants after cancellation even if the transport calls a removed subscriber', async () => {
    const host = createRoomInvitation(), requesterSk = generateSecretKey(), controller = new AbortController()
    let receive!: (event: Event) => void
    const publish = vi.fn(async (_event: Event) => {}), off = vi.fn()
    const transport: RelayTransport = { publish, close: vi.fn(), subscribe: (_filters, callback) => { receive = callback; return off } }
    const join = requestRoomAdmissionCapability({ transport, invitation: host.invitation, requesterSk, now: () => NOW, signal: controller.signal })
    const rejected = expect(join).rejects.toMatchObject({ name: 'AbortError' })
    const request = publish.mock.calls[0][0]
    controller.abort(); await rejected
    receive(encodeInvitationGrant({ ...host, requester: getPublicKey(requesterSk), request: request.id, roomSecret, now: NOW }))
    expect(off).toHaveBeenCalledTimes(1)
    expect(requesterSk.some(byte => byte !== 0)).toBe(true)
  })
})
