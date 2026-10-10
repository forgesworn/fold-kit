#!/usr/bin/env node
// Synthetic known-answer fixtures for the encrypted invitation account proof.
// Every key and randomness draw is fixed and public; no production credentials.
import { writeFileSync } from 'node:fs'
import { getPublicKey } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/hashes/utils'
import { seed32, deriveSecretKey, finalizeDeterministic, withStubbedRandomness } from '../vectors/lib/determinism.mjs'
import { roomInvitation, deriveInvitationId, encodeInvitationAccountProof, encodeInvitationRequest } from '../dist/index.js'

const now = 1_800_000_000
const bearer = seed32('invitation-account/bearer')
const inviterSk = deriveSecretKey('invitation-account/inviter')
const accountSk = deriveSecretKey('invitation-account/account')
const requesterSk = deriveSecretKey('invitation-account/requester')
const invitation = roomInvitation(bearer, getPublicKey(inviterSk))
const participant = getPublicKey(accountSk), device = getPublicKey(requesterSk)
const proofAux = seed32('invitation-account/proof-aux')
const identity = { pubkey: participant, signEvent: async unsigned => finalizeDeterministic(unsigned, accountSk, proofAux) }
const plain = ({ id, pubkey, created_at, kind, tags, content, sig }) => ({ id, pubkey, created_at, kind, tags, content, sig })
const proof = plain(await encodeInvitationAccountProof({ invitation, device, identity, now }))
const input = { now, bearerHex: bytesToHex(bearer), inviter: invitation.inviter, accountSkHex: bytesToHex(accountSk), requesterSkHex: bytesToHex(requesterSk), proofAuxHex: bytesToHex(proofAux), participant, device }
const requestKey = hkdf(sha256, bearer, undefined, 'kithmoot/v2/invitation-request-key', 32)
const cases = []
for (const name of ['verified', 'legacy', 'forged-signature', 'substituted-device']) {
  const nonce = seed32(`invitation-account/${name}/nonce`), aux = seed32(`invitation-account/${name}/aux`)
  let event
  if (name === 'verified' || name === 'legacy') {
    event = withStubbedRandomness([nonce, aux], () => encodeInvitationRequest({ invitation, requesterSk, now, participant, ...(name === 'verified' ? { accountProof: proof } : {}) }))
  } else {
    const accountProof = name === 'forged-signature' ? { ...proof, sig: '00'.repeat(64) }
      : plain(await encodeInvitationAccountProof({ invitation, device: getPublicKey(deriveSecretKey('invitation-account/other-device')), identity, now }))
    // A legitimate bearer holder can encrypt/sign an arbitrary unproved claim.
    event = finalizeDeterministic({ kind: 20466, created_at: now, tags: [['d', deriveInvitationId(invitation)], ['p', invitation.inviter]], content: nip44.v2.encrypt(JSON.stringify({ v: 1, device, participant, accountProof }), requestKey, nonce) }, requesterSk, aux)
  }
  cases.push({ name, nonceHex: bytesToHex(nonce), auxHex: bytesToHex(aux), event: plain(event), verifiedParticipant: name === 'verified' ? participant : null })
}
requestKey.fill(0)
writeFileSync(new URL('../vectors/invitation-account-vectors.json', import.meta.url), JSON.stringify({ protocolVersion: 'kithmoot/v2/invitation-account-proof', syntheticOnly: true, input, proof, cases }, null, 2) + '\n')
