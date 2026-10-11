#!/usr/bin/env node
// Synthetic public test keys only. Independent canonical composer and Node
// HKDF/SHA256 oracle; fixed Schnorr auxiliary randomness/NIP44 nonces are for
// these known-answer vectors only and never exposed by the production codec.
import { createHash, hkdfSync } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { nip44 } from 'nostr-tools'
import { getPublicKey, getEventHash } from 'nostr-tools/pure'
import { schnorr } from '@noble/curves/secp256k1.js'
const sk = n => new Uint8Array(32).fill(n)
const hex = b => Buffer.from(b).toString('hex')
const json = JSON.stringify
const hash = v => createHash('sha256').update(json(v)).digest('hex')
const derive = (key, salt, label) => new Uint8Array(hkdfSync('sha256', key, salt, Buffer.from(label), 32))
const pk = getPublicKey, now = 1791720000, root = sk(1), req = sk(2), bearer = sk(10), box = '11'.repeat(32)
const label = suffix => 'kithmoot/v4/' + suffix
const invitationId = hex(derive(bearer, Buffer.from(pk(root), 'hex'), label('mls-invitation-id')))
const fragment = Buffer.from(json([4, Buffer.from(bearer).toString('base64url'), pk(root)])).toString('base64url')
function sign(unsigned, key) {
  const event = { ...unsigned, pubkey: pk(key) }
  const id = getEventHash(event)
  return { id, pubkey: event.pubkey, created_at: event.created_at, kind: event.kind, tags: event.tags, content: event.content,
    sig: hex(schnorr.sign(Buffer.from(id, 'hex'), key, sk(31))) }
}
const array = e => [e.id, e.pubkey, e.created_at, e.kind, e.tags, e.content, e.sig]
const credential = (a, d) => array(sign({ kind: 20460, created_at: now - 1, tags: [['d', pk(sk(a))], ['device', pk(sk(d))], ['expiration', String(now + 86400)], ['scope', 'person']], content: '' }, sk(a)))
const requestCore = [4, label('mls-request'), invitationId, pk(root), pk(req), '12'.repeat(32), '13'.repeat(32), pk(sk(3)), pk(sk(4)), pk(sk(5)), pk(sk(8)), credential(3, 5), box, '18446744073709551615', now + 3600, now, now + 90]
const proofs = (core, roles, keys, kind, created_at) => roles.map((role, i) => array(sign({ kind, created_at, tags: [['t', label(role)]], content: json([4, hash(core)]) }, sk(keys[i]))))
const requestProofs = proofs(requestCore, ['mls-joiner-account-proof', 'mls-browser-device-proof', 'mls-engine-device-proof'], [3, 4, 5], 20466, now)
const base = nip44.v2.utils.getConversationKey(req, pk(root))
const requestKey = derive(base, bearer, label('mls-request-key')), answerKey = derive(base, bearer, label('mls-answer-key'))
function padded(core, ps) {
  const length = Buffer.byteLength(json([4, core, ps, '']))
  if (length > 16384) throw new Error('oversized synthetic vector')
  return json([4, core, ps, '0'.repeat(16384 - length)])
}
const requestEvent = sign({ kind: 20466, created_at: now, tags: [['d', invitationId], ['p', pk(root)], ['expiration', String(now + 90)]], content: nip44.v2.encrypt(padded(requestCore, requestProofs), requestKey, sk(21)) }, req)
const allowCore = [4, label('mls-answer'), 'allow', invitationId, pk(root), requestEvent.id, hash(requestCore), requestCore[5], requestCore[6], requestCore[7], requestCore[8], requestCore[9], requestCore[10], box, requestCore[13], pk(sk(6)), pk(sk(7)), credential(6, 7), pk(sk(9)), box, box, '14'.repeat(32), '15'.repeat(32), now + 1800, now + 86400, now + 1, now + 90]
const allowProofs = proofs(allowCore, ['mls-keeper-account-proof', 'mls-keeper-device-proof'], [6, 7], 20467, now + 1)
const denyCore = [4, label('mls-answer'), 'deny', invitationId, pk(root), requestEvent.id, hash(requestCore), requestCore[5], requestCore[6], now + 1, now + 90]
const tags = [['p', pk(req)], ['e', requestEvent.id], ['expiration', String(now + 90)]]
const answer = (core, ps, nonce) => sign({ kind: 20467, created_at: now + 1, tags, content: nip44.v2.encrypt(padded(core, ps), answerKey, sk(nonce)) }, root)
const output = {
  description: 'Synthetic public test secrets only; independently composed v4 canonical arrays, Node crypto HKDF/SHA256, fixed test-only randomness. No actual admission or browser acceptance.',
  now, rootSecretHex: hex(root), requestSecretHex: hex(req), bearerHex: hex(bearer), fragment, invitationId, baseKeyHex: hex(base), requestKeyHex: hex(requestKey), answerKeyHex: hex(answerKey),
  requestCore: json(requestCore), requestProofs: json(requestProofs), requestDigest: hash(requestCore), requestEvent: json(requestEvent),
  allowCore: json(allowCore), allowProofs: json(allowProofs), allowDigest: hash(allowCore), allowEvent: json(answer(allowCore, allowProofs, 22)),
  denyCore: json(denyCore), denyDigest: hash(denyCore), denyEvent: json(answer(denyCore, [], 23)), plaintextBytes: 16384, ciphertextCharacters: 21936,
}
writeFileSync('vectors/mls-admission-v4.json', JSON.stringify(output, null, 2) + '\n')
