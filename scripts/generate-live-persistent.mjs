#!/usr/bin/env node
// Synthetic deterministic keys only. Never use these fixtures as room credentials.
import { writeFileSync } from 'node:fs'
import { bytesToHex } from '@noble/hashes/utils'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { getPublicKey } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { deriveSecretKey, seed32, withStubbedRandomness, finalizeDeterministic } from '../vectors/lib/determinism.mjs'
import { deriveRoom, encodePersistentInvitation, encodeLivePersistentDescriptor,
  encodeLivePersistentRequest, encodeLivePersistentAnswer } from '../dist/index.js'

const now = 1_800_000_000
const root = deriveSecretKey('persistent-live/root')
const requester = deriveSecretKey('persistent-live/requester')
const other = deriveSecretKey('persistent-live/other')
const secret = seed32('persistent-live/room-secret')
const bearer = seed32('persistent-live/bearer')
const invitation = { bearer, inviter: getPublicKey(root), persistent: true }
const roomId = deriveRoom(secret).roomId
const ctx = { invitation, roomId }
const plain = e => ({ id: e.id, pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content, sig: e.sig })
const recorded = (label, fn) => {
  const random = [seed32(`${label}/nonce`), seed32(`${label}/aux`)]
  return { event: plain(withStubbedRandomness(random, fn)), randomHex: random.map(bytesToHex) }
}
const welcome = recorded('persistent-live/welcome', () => encodePersistentInvitation({ invitation,
  inviterSk: root, roomSecret: secret, now: now - 10, endsAt: now + 3600, destruct: true, relays: ['wss://relay.example/'] }))
const request = recorded('persistent-live/request', () => encodeLivePersistentRequest({ ...ctx, now, requesterSk: requester }))
const answer = recorded('persistent-live/answer', () => encodeLivePersistentAnswer({ ...ctx, now: now + 1,
  request: request.event, invitationEvent: welcome.event, inviterSk: root, epoch: 4 }))
const requestKey = hkdf(sha256, bearer, undefined, 'kithmoot/v1/persistent-live/request-key', 32)
const answerKey = nip44.v2.utils.getConversationKey(root, getPublicKey(requester))
const shared = { bearerHex: bytesToHex(bearer), inviter: invitation.inviter, roomId, now: now + 2 }
const cases = []
function add(name, operation, input, accepted, result = undefined) {
  cases.push({ name, kind: accepted ? 'positive' : 'negative', operation,
    input: { ...shared, ...input }, output: { accepted, ...(result ? { result } : {}) } })
}
add('descriptor', 'descriptor', { encoded: encodeLivePersistentDescriptor(ctx) }, true, { roomId })
add('request', 'request', { event: request.event, requesterSkHex: bytesToHex(requester), randomHex: request.randomHex }, true,
  { requestId: request.event.id, requester: request.event.pubkey, createdAt: now, expiresAt: now + 90 })
const answerInput = { event: answer.event, request: request.event, requesterSkHex: bytesToHex(requester) }
add('answer', 'answer', { ...answerInput, inviterSkHex: bytesToHex(root), invitationEvent: welcome.event, epoch: 4, randomHex: answer.randomHex }, true,
  { secretHex: bytesToHex(secret), persistent: true, epoch: 0, epochHint: 4, endsAt: now + 3600,
    destruct: true, relays: ['wss://relay.example/'], requestId: request.event.id, expiresAt: now + 31 })
const sign = (e, changes, sk = root) => plain(finalizeDeterministic({ kind: e.kind, created_at: e.created_at,
  content: e.content, tags: e.tags, ...changes }, sk, seed32('persistent-live/negative-aux')))
const changedBody = (e, changes, isRequest = false) => {
  const key = isRequest ? requestKey : answerKey
  const raw = JSON.parse(nip44.v2.decrypt(e.content, key))
  return sign(e, { content: nip44.v2.encrypt(JSON.stringify({ ...raw, ...changes }), key,
    seed32('persistent-live/negative-nonce')) }, isRequest ? requester : root)
}
const negativeAnswer = (name, changes) => add(name, 'answer', { ...answerInput, ...changes }, false)
negativeAnswer('answer-expired', { now: now + 31 })
negativeAnswer('answer-clock-skew', { now: now - 5 })
negativeAnswer('answer-wrong-key', { requesterSkHex: bytesToHex(other) })
negativeAnswer('answer-wrong-room', { roomId: 'a'.repeat(64) })
negativeAnswer('answer-wrong-bearer', { bearerHex: bytesToHex(seed32('persistent-live/other-bearer')) })
negativeAnswer('answer-wrong-authority', { event: sign(answer.event, {}, other) })
negativeAnswer('answer-wrong-request', { event: changedBody(answer.event, { request: 'a'.repeat(64) }) })
negativeAnswer('answer-negative-epoch', { event: changedBody(answer.event, { epoch: -1 }) })
negativeAnswer('answer-duplicate-tag', { event: sign(answer.event, { tags: [...answer.event.tags, answer.event.tags[0]] }) })
negativeAnswer('answer-wrong-profile', { event: changedBody(answer.event, { profile: 'legacy' }) })
negativeAnswer('answer-bad-invitation-signature', { event: changedBody(answer.event, { invitation: { ...welcome.event, sig: '0'.repeat(128) } }) })
negativeAnswer('answer-embedded-future', { event: changedBody(answer.event, { invitation: sign(welcome.event, { created_at: now + 7 }) }) })
negativeAnswer('answer-cached-invitation-alone', { event: welcome.event })
negativeAnswer('answer-extended-expiry', { event: sign(answer.event, { tags: answer.event.tags.map(t => t[0] === 'expiration' ? ['expiration', String(now + 32)] : t) }) })
const rawAnswer = nip44.v2.decrypt(answer.event.content, answerKey)
negativeAnswer('answer-duplicate-json-field', { event: sign(answer.event, { content: nip44.v2.encrypt(rawAnswer.replace('{', '{"v":1,'), answerKey, seed32('persistent-live/duplicate-nonce')) }) })
add('request-expired', 'request', { event: request.event, now: now + 90 }, false)
add('request-clock-skew', 'request', { event: request.event, now: now - 6 }, false)
add('request-wrong-requester', 'request', { event: changedBody(request.event, { requester: getPublicKey(other) }, true) }, false)
add('request-extended-expiry', 'request', { event: sign(request.event, { tags: request.event.tags.map(t => t[0] === 'expiration' ? ['expiration', String(now + 91)] : t) }, requester) }, false)
add('descriptor-wrong-authority', 'descriptor', { encoded: encodeLivePersistentDescriptor(ctx), inviter: getPublicKey(other) }, false)
add('descriptor-padding', 'descriptor', { encoded: encodeLivePersistentDescriptor(ctx) + '=' }, false)

const out = { protocolVersion: 'kithmoot/v1', profile: 'persistent-live-v1',
  note: 'Synthetic keys; codec evidence only, no lifecycle or epoch admission claim.',
  derivations: { requestKeyHex: bytesToHex(requestKey), requestPlaintext: nip44.v2.decrypt(request.event.content, requestKey),
    answerPlaintext: rawAnswer, welcomeRandomHex: welcome.randomHex, inviterSkHex: bytesToHex(root), secretHex: bytesToHex(secret) },
  groups: { livePersistentAdmission: cases } }
writeFileSync(new URL('../vectors/live-persistent-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n')
console.log(`${cases.length} live persistent admission vectors`)
