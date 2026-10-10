import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { getPublicKey, verifyEvent, getEventHash } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { hexToBytes } from '@noble/hashes/utils'
import { schnorr } from '@noble/curves/secp256k1.js'
import { finalizeDeterministic, withStubbedRandomness } from './lib/determinism.mjs'
import { roomInvitation, deriveInvitationId, encodeInvitationAccountProof, encodeInvitationRequest, decodeInvitationRequest } from '../src/invitation.js'

const vector = JSON.parse(readFileSync(new URL('./invitation-account-vectors.json', import.meta.url), 'utf8'))
const { input } = vector
const invitation = roomInvitation(hexToBytes(input.bearerHex), input.inviter)
const requesterSk = hexToBytes(input.requesterSkHex)
const plain = ({ id, pubkey, created_at, kind, tags, content, sig }: any) => ({ id, pubkey, created_at, kind, tags, content, sig })

describe('invitation account known answers', () => {
  it('rebuilds the new proof profile and verifies its actual account signature', async () => {
    const accountSk = hexToBytes(input.accountSkHex)
    const proof = await encodeInvitationAccountProof({ invitation, device: input.device, now: input.now, identity: {
      pubkey: getPublicKey(accountSk), signEvent: async unsigned => finalizeDeterministic(unsigned, accountSk, hexToBytes(input.proofAuxHex)),
    } })
    expect(plain(proof)).toEqual(vector.proof)
    expect(proof.tags).toEqual([['t', 'kithmoot/v2/invitation-account-proof'], ['d', deriveInvitationId(invitation)], ['p', input.inviter]])
    expect(proof.content).toBe(JSON.stringify({ v: 1, device: input.device }))
    expect(schnorr.verify(hexToBytes(proof.sig), hexToBytes(getEventHash(proof)), hexToBytes(input.participant))).toBe(true)
  })

  for (const fixture of vector.cases) it(`decodes ${fixture.name} without granting authority to a claim`, () => {
    expect(verifyEvent(fixture.event)).toBe(true)
    const decoded = decodeInvitationRequest(fixture.event, { invitation, now: input.now })
    expect(decoded).toEqual({ device: input.device, request: fixture.event.id, participant: input.participant, ...(fixture.verifiedParticipant ? { verifiedParticipant: fixture.verifiedParticipant } : {}) })
    expect(decodeInvitationRequest(fixture.event, { invitation, now: input.now + 91 })).toBeNull()
    expect(decodeInvitationRequest(fixture.event, { invitation: roomInvitation(new Uint8Array(32).fill(7), input.inviter), now: input.now })).toBeNull()
    const key = hkdf(sha256, invitation.bearer, undefined, 'kithmoot/v2/invitation-request-key', 32)
    const body = JSON.parse(nip44.v2.decrypt(fixture.event.content, key))
    const reconstructed = finalizeDeterministic({ kind: 20466, created_at: input.now, tags: [['d', deriveInvitationId(invitation)], ['p', input.inviter]], content: nip44.v2.encrypt(JSON.stringify(body), key, hexToBytes(fixture.nonceHex)) }, requesterSk, hexToBytes(fixture.auxHex))
    expect(plain(reconstructed)).toEqual(plain(fixture.event))
    key.fill(0)
    if (fixture.name === 'verified' || fixture.name === 'legacy') {
      const encoded = withStubbedRandomness([hexToBytes(fixture.nonceHex), hexToBytes(fixture.auxHex)], () => encodeInvitationRequest({ invitation, requesterSk, now: input.now, participant: input.participant, ...(fixture.name === 'verified' ? { accountProof: vector.proof } : {}) }))
      expect(plain(encoded)).toEqual(plain(fixture.event))
    }
  })
})
