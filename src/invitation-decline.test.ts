import { describe, expect, it } from 'vitest'
import { nip44 } from 'nostr-tools'
import { finalizeEvent, generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure'
import { SimRelay, SimTransport } from '../test/sim-relay.js'
import { createRoomInvitation, decodeInvitationGrant, decodeInvitationRequest, decodeRoomAdmissionGrant,
  deriveInvitationId, encodeInvitationGrant, requestRoomAdmissionCapability } from './invitation.js'
import { decodeInvitationDecline, encodeInvitationDecline, InvitationDeclinedError } from './invitation-decline.js'

const now = 1_800_000_000
function fixture() {
  const host = createRoomInvitation(), requesterSk = generateSecretKey(), request = 'ab'.repeat(32)
  const opts = { invitation: host.invitation, requesterSk, request, now }
  const encode = { invitation: host.invitation, inviterSk: host.inviterSk, requester: getPublicKey(requesterSk), request, now }
  return { host, requesterSk, opts, encode, event: encodeInvitationDecline(encode) }
}

describe('authenticated invitation refusals', () => {
  it('returns only the refusing responder and request; legacy grant readers get no capability', () => {
    const f = fixture()
    expect(decodeInvitationDecline(f.event, f.opts)).toEqual({ request: f.encode.request, responder: f.host.invitation.inviter })
    expect(decodeInvitationGrant(f.event, f.opts)).toBeNull()
    expect(decodeRoomAdmissionGrant(f.event, f.opts)).toBeNull()
    const body = JSON.parse(nip44.v2.decrypt(f.event.content, nip44.v2.utils.getConversationKey(f.requesterSk, f.event.pubkey)))
    expect(Object.keys(body).sort()).toEqual(['decision', 'delegation', 'request', 'v'])
    expect(body.delegation).toEqual([])
  })

  it.each(['other-request', 'other-device', 'other-invitation', 'expired', 'future', 'invalid-clock', 'cached-forgery', 'wrong-kind'])('rejects %s', attack => {
    const f = fixture(); let event = f.event; let opts = f.opts
    if (attack === 'other-request') opts = { ...opts, request: 'cd'.repeat(32) }
    if (attack === 'other-device') opts = { ...opts, requesterSk: generateSecretKey() }
    if (attack === 'other-invitation') opts = { ...opts, invitation: createRoomInvitation().invitation }
    if (attack === 'expired') opts = { ...opts, now: now + 91 }
    if (attack === 'future') opts = { ...opts, now: now - 91 }
    if (attack === 'invalid-clock') opts = { ...opts, now: NaN }
    if (attack === 'cached-forgery') event = { ...event, sig: '00'.repeat(64) } as Event
    if (attack === 'wrong-kind') event = finalizeEvent({ ...event, kind: 20466 }, f.host.inviterSk)
    expect(decodeInvitationDecline(event, opts)).toBeNull()
  })

  it.each(['unauthorised', 'duplicate-recipient', 'duplicate-rendezvous', 'contains-secret', 'wrong-version', 'wrong-decision'])('rejects a signed %s envelope', attack => {
    const f = fixture(), signer = attack === 'unauthorised' ? generateSecretKey() : f.host.inviterSk
    const body: Record<string, unknown> = { v: 3, decision: 'declined', request: f.opts.request, delegation: [] }
    if (attack === 'contains-secret') body.secret = 'secret'
    if (attack === 'wrong-version') body.v = 2
    if (attack === 'wrong-decision') body.decision = 'admitted'
    const tags = f.event.tags.map(t => [...t])
    if (attack === 'duplicate-recipient') tags.push(['p', f.encode.requester])
    if (attack === 'duplicate-rendezvous') tags.push(['d', deriveInvitationId(f.host.invitation)])
    const event = finalizeEvent({ kind: 20467, created_at: now, tags,
      content: nip44.v2.encrypt(JSON.stringify(body), nip44.v2.utils.getConversationKey(signer, f.encode.requester)) }, signer)
    expect(decodeInvitationDecline(event, f.opts)).toBeNull()
  })

  it('accepts a current delegated responder and rejects it once its authority expires', () => {
    const f = fixture(), delegateSk = generateSecretKey()
    const grant = encodeInvitationGrant({ ...f.encode, requester: getPublicKey(delegateSk), roomSecret: new Uint8Array(32).fill(9), delegationTtlSeconds: 10 })
    const delegated = decodeRoomAdmissionGrant(grant, { ...f.opts, requesterSk: delegateSk })!
    expect(delegated).not.toBeNull()
    const event = encodeInvitationDecline({ ...f.encode, inviterSk: delegateSk, delegation: delegated.delegate.chain })
    expect(decodeInvitationDecline(event, f.opts)?.responder).toBe(getPublicKey(delegateSk))
    expect(decodeInvitationDecline(event, { ...f.opts, now: now + 11 })).toBeNull()
    expect(() => encodeInvitationDecline({ ...f.encode, inviterSk: delegateSk })).toThrow(/not delegated/)
  })

  it('rejects invalid encoder inputs', () => {
    const f = fixture()
    expect(() => encodeInvitationDecline({ ...f.encode, now: -1 })).toThrow(/time/)
    expect(() => encodeInvitationDecline({ ...f.encode, request: 'invalid' })).toThrow(/hex/)
    expect(() => encodeInvitationDecline({ ...f.encode, inviterSk: new Uint8Array(5) })).toThrow(/32 bytes/)
  })

  it('ends a real simulated guest exchange on refusal and preserves the caller-owned key', async () => {
    const f = fixture(), relay = new SimRelay(), host = new SimTransport(relay), guest = new SimTransport(relay)
    let requests = 0
    const unsubscribe = host.subscribe([{ kinds: [20466] }], event => {
      const request = decodeInvitationRequest(event, { invitation: f.host.invitation, now })!
      requests++
      void host.publish(encodeInvitationDecline({ ...f.encode, request: request.request, requester: request.device }))
    })
    const before = [...f.requesterSk]
    try {
      await expect(requestRoomAdmissionCapability({ transport: guest, invitation: f.host.invitation,
        requesterSk: f.requesterSk, now: () => now, timeoutMs: 2000, retryMs: 10 })).rejects.toBeInstanceOf(InvitationDeclinedError)
      await new Promise(resolve => setTimeout(resolve, 40))
      expect(requests).toBe(1)
      expect([...f.requesterSk]).toEqual(before)
    } finally { unsubscribe() }
  })
})
