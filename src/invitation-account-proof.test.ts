import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey, verifiedSymbol, finalizeEvent } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { localIdentity } from './identity.js'
import { createRoomInvitation, encodeInvitationAccountProof, encodeInvitationRequest, decodeInvitationRequest } from './invitation.js'

const NOW = 1_800_000_000

describe('invitation account proof', () => {
  it('refuses invalid proof clocks before asking the account to sign', async () => {
    const host = createRoomInvitation(), identity = localIdentity(generateSecretKey()), device = getPublicKey(generateSecretKey())
    for (const now of [NaN, Infinity, -1, Number.MAX_SAFE_INTEGER + 1]) await expect(encodeInvitationAccountProof({ invitation: host.invitation, identity, device, now })).rejects.toThrow('invalid invitation account proof time')
  })
  it('keeps a legacy claimed account unverified', () => {
    const host = createRoomInvitation(), requesterSk = generateSecretKey(), participant = getPublicKey(generateSecretKey())
    const event = encodeInvitationRequest({ invitation: host.invitation, requesterSk, participant, now: NOW })
    expect(decodeInvitationRequest(event, { invitation: host.invitation, now: NOW })).toEqual({ device: getPublicKey(requesterSk), request: event.id, participant })
  })

  it('proves an account for exactly its invitation, ephemeral device and request time', async () => {
    const host = createRoomInvitation(), requesterSk = generateSecretKey(), identity = localIdentity(generateSecretKey())
    const accountProof = await encodeInvitationAccountProof({ invitation: host.invitation, device: getPublicKey(requesterSk), identity, now: NOW })
    const event = encodeInvitationRequest({ invitation: host.invitation, requesterSk, participant: identity.pubkey, accountProof, now: NOW })
    expect(decodeInvitationRequest(event, { invitation: host.invitation, now: NOW })).toEqual({ device: getPublicKey(requesterSk), request: event.id, participant: identity.pubkey, verifiedParticipant: identity.pubkey })
    expect(event.tags.flat()).not.toContain(identity.pubkey)
    expect(event.content).not.toContain(identity.pubkey)
    expect(event.content).not.toContain(accountProof.sig)
  })

  it('refuses account, device, invitation and timestamp substitution at encoding', async () => {
    const host = createRoomInvitation(), other = createRoomInvitation(), requesterSk = generateSecretKey(), identity = localIdentity(generateSecretKey())
    const accountProof = await encodeInvitationAccountProof({ invitation: host.invitation, device: getPublicKey(requesterSk), identity, now: NOW })
    const options = { invitation: host.invitation, requesterSk, participant: identity.pubkey, accountProof, now: NOW }
    for (const changed of [{ participant: getPublicKey(generateSecretKey()) }, { requesterSk: generateSecretKey() }, { invitation: other.invitation }, { now: NOW + 1 }, { participant: undefined }]) {
      expect(() => encodeInvitationRequest({ ...options, ...changed })).toThrow('invalid invitation account proof')
    }
  })

  it('freshly verifies signatures even when a caller supplies a cached verdict', async () => {
    const host = createRoomInvitation(), requesterSk = generateSecretKey(), identity = localIdentity(generateSecretKey())
    const accountProof = await encodeInvitationAccountProof({ invitation: host.invitation, device: getPublicKey(requesterSk), identity, now: NOW })
    accountProof.sig = '00'.repeat(64)
    accountProof[verifiedSymbol] = true
    expect(() => encodeInvitationRequest({ invitation: host.invitation, requesterSk, participant: identity.pubkey, accountProof, now: NOW })).toThrow('invalid invitation account proof')
  })

  it('never upgrades a forged or substituted wire proof into a verified account', async () => {
    const host = createRoomInvitation(), requesterSk = generateSecretKey(), identity = localIdentity(generateSecretKey())
    const accountProof = await encodeInvitationAccountProof({ invitation: host.invitation, device: getPublicKey(requesterSk), identity, now: NOW })
    const key = hkdf(sha256, host.invitation.bearer, undefined, 'kithmoot/v2/invitation-request-key', 32)
    for (const proof of [null, [], { ...accountProof, sig: '00'.repeat(64) }, { ...accountProof, created_at: NOW + 1 }, { ...accountProof, content: JSON.stringify({ v: 1, device: getPublicKey(generateSecretKey()) }) }, { ...accountProof, pubkey: getPublicKey(generateSecretKey()) }]) {
      // A real holder can sign the outer request and encrypt arbitrary claims.
      // It cannot sign an invited account's device authorisation.
      const event = finalizeEvent({ kind: 20466, created_at: NOW, tags: [['d', accountProof.tags[1][1]], ['p', host.invitation.inviter]], content: nip44.v2.encrypt(JSON.stringify({ v: 1, device: getPublicKey(requesterSk), participant: identity.pubkey, accountProof: proof }), key) }, requesterSk)
      const decoded = decodeInvitationRequest(event, { invitation: host.invitation, now: NOW })
      expect(decoded?.participant).toBe(identity.pubkey)
      expect(decoded?.verifiedParticipant).toBeUndefined()
    }
    key.fill(0)
  })

  it('refuses a signer returning a different account or modifying the signed context', async () => {
    const host = createRoomInvitation(), identity = localIdentity(generateSecretKey()), other = localIdentity(generateSecretKey()), device = getPublicKey(generateSecretKey())
    await expect(encodeInvitationAccountProof({ invitation: host.invitation, device, now: NOW, identity: { pubkey: identity.pubkey, signEvent: unsigned => other.signEvent(unsigned) } })).rejects.toThrow('invalid invitation account proof from signer')
    await expect(encodeInvitationAccountProof({ invitation: host.invitation, device, now: NOW, identity: { pubkey: identity.pubkey, signEvent: unsigned => identity.signEvent({ ...unsigned, content: '' }) } })).rejects.toThrow('invalid invitation account proof from signer')
  })
})
