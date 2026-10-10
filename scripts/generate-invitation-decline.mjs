#!/usr/bin/env node
// Fixed public keys and randomness: synthetic wire fixtures, never credentials.
import { writeFileSync } from 'node:fs'
import { getPublicKey } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { bytesToHex } from '@noble/hashes/utils'
import { seed32, deriveSecretKey, finalizeDeterministic, withStubbedRandomness } from '../vectors/lib/determinism.mjs'
import { roomInvitation, deriveInvitationId, encodeInvitationDecline } from '../dist/index.js'

const now = 1_800_000_000
const inviterSk = deriveSecretKey('invitation-decline/inviter')
const requesterSk = deriveSecretKey('invitation-decline/requester')
const outsiderSk = deriveSecretKey('invitation-decline/outsider')
const bearer = seed32('invitation-decline/bearer')
const invitation = roomInvitation(bearer, getPublicKey(inviterSk))
const requester = getPublicKey(requesterSk), request = bytesToHex(seed32('invitation-decline/request'))
const plain = ({ id, pubkey, created_at, kind, tags, content, sig }) => ({ id, pubkey, created_at, kind, tags, content, sig })
const cases = []
for (const name of ['declined', 'wrong-request', 'unauthorised', 'legacy-version']) {
  const nonce = seed32(`invitation-decline/${name}/nonce`), aux = seed32(`invitation-decline/${name}/aux`)
  let event
  if (name === 'declined') {
    event = withStubbedRandomness([nonce, aux], () => encodeInvitationDecline({ invitation, inviterSk, requester, request, now }))
  } else {
    const signer = name === 'unauthorised' ? outsiderSk : inviterSk
    event = finalizeDeterministic({ kind: 20467, created_at: now,
      tags: [['d', deriveInvitationId(invitation)], ['p', requester]],
      content: nip44.v2.encrypt(JSON.stringify({ v: name === 'legacy-version' ? 2 : 3, decision: 'declined',
        request: name === 'wrong-request' ? bytesToHex(seed32('invitation-decline/other-request')) : request,
        delegation: [] }), nip44.v2.utils.getConversationKey(signer, requester), nonce),
    }, signer, aux)
  }
  cases.push({ name, accepted: name === 'declined', nonceHex: bytesToHex(nonce), auxHex: bytesToHex(aux), event: plain(event) })
}
writeFileSync(new URL('../vectors/invitation-decline-vectors.json', import.meta.url), JSON.stringify({
  protocolVersion: 'invitation-reply/v3/declined', syntheticOnly: true,
  input: { now, bearerHex: bytesToHex(bearer), inviterSkHex: bytesToHex(inviterSk), requesterSkHex: bytesToHex(requesterSk),
    outsiderSkHex: bytesToHex(outsiderSk), request }, cases,
}, null, 2) + '\n')
