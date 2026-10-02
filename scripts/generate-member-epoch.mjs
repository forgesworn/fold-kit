#!/usr/bin/env node
// Known-answer vectors for member-to-member epoch catch-up (src/epoch-commit.ts,
// src/member-epoch.ts and the `commit` option on `encodeRekeyEvent`). See
// docs/member-epoch-catch-up.md.
//
// Written in KithMoot's vector format (`protocolVersion`, `groups`, and per
// vector `name`/`kind`/`note`/`input`/`output`), so the file can be copied
// verbatim into KithMoot's `vectors/` and from there into KithMoot Android's,
// as the circle vectors are. Every input is a fixed labelled value from
// `vectors/lib/determinism.mjs`, and every random draw a real encoder makes
// (NIP-44 nonces, BIP-340 aux-rand) is recorded beside the event it went
// into, in draw order, so another implementation can rebuild each event byte
// for byte with explicit nonces.
//
// Run after `npm run build`: `npm run generate-member-epoch`. Verified against
// `src/` directly by `vectors/verify-member-epoch.test.ts`.
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bytesToHex } from '@noble/hashes/utils'
import { getPublicKey } from 'nostr-tools/pure'
import { seed32, deriveSecretKey, finalizeDeterministic, withStubbedRandomness } from '../vectors/lib/determinism.mjs'
import {
  deriveRoom,
  deriveEpoch,
  createDeviceCredential,
  encodeRekeyEvent,
  epochCommitment,
  deriveMemberEpochRequestKey,
  encodeMemberEpochRequest,
  decodeMemberEpochRequest,
  encodeMemberEpochGrant,
  decodeMemberEpochGrant,
  readRekeyEvidence,
} from '../dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const outPath = join(here, '..', 'vectors', 'member-epoch-vectors.json')
const nostrToolsVersion = JSON.parse(
  (await import('node:fs')).readFileSync(join(here, '..', 'node_modules', 'nostr-tools', 'package.json'), 'utf8'),
).version

// --- Fixed inputs ------------------------------------------------------------

const NOW = 1_800_000_000
const ROOM_SECRET = seed32('member-epoch/room-secret')
const { roomId, roomKey } = deriveRoom(ROOM_SECRET)
const AUTHORITY_SK = deriveSecretKey('member-epoch/authority')
const AUTHORITY = getPublicKey(AUTHORITY_SK)
const MEMBER_DEVICE_SK = deriveSecretKey('member-epoch/member-device')
const MEMBER_DEVICE = getPublicKey(MEMBER_DEVICE_SK)
const REQUESTER_SK = deriveSecretKey('member-epoch/requester-participant')
const REQUESTER = getPublicKey(REQUESTER_SK)
const REQUESTER_DEVICE_SK = deriveSecretKey('member-epoch/requester-device')
const REQUESTER_DEVICE = getPublicKey(REQUESTER_DEVICE_SK)
const GONE = getPublicKey(deriveSecretKey('member-epoch/removed-participant'))
const EPOCH_1 = { epoch: 1, secret: seed32('member-epoch/epoch-1-secret') }
const EPOCH_2 = { epoch: 2, secret: seed32('member-epoch/epoch-2-secret') }
const FORGED_SECRET = seed32('member-epoch/forged-secret')

const r = (label) => seed32(`member-epoch/random/${label}`)
const hex = bytesToHex

function plain(event) {
  const { id, pubkey, created_at, kind, tags, content, sig } = event
  return { id, pubkey, created_at, kind, tags, content, sig }
}

/** Run a real encoder with recorded randomness; return the event and the draws. */
function recorded(labels, fn) {
  const draws = labels.map(r)
  const event = withStubbedRandomness(draws, fn)
  return { event: plain(event), randomHex: draws.map(hex) }
}

const e0 = deriveEpoch({ epoch: 0, secret: ROOM_SECRET })
const e1 = deriveEpoch(EPOCH_1)

function rekey(label, { current, next, removed = [], commit, closed }) {
  return recorded([`${label}/seal`, `${label}/body`, `${label}/aux`].slice(closed ? 1 : 0), () =>
    encodeRekeyEvent({
      roomId,
      authoritySk: AUTHORITY_SK,
      current,
      next,
      recipients: [MEMBER_DEVICE],
      removed,
      ...(commit ? { commit: true } : {}),
      ...(closed ? { closed: true } : {}),
      now: NOW - 1000 + next.epoch,
    }),
  )
}

// Epoch 1 is a legacy rekey (no commitment); epoch 2 carries one and removes GONE.
const rekey1Legacy = rekey('rekey-1-legacy', { current: e0, next: EPOCH_1 })
const rekey2 = rekey('rekey-2', { current: e1, next: EPOCH_2, removed: [GONE], commit: true })
const rekey1Committed = rekey('rekey-1-committed', { current: e0, next: EPOCH_1, commit: true })
const rekey2RemovesRequester = rekey('rekey-2-removes-requester', { current: e1, next: EPOCH_2, removed: [REQUESTER], commit: true })
const rekey2Closed = rekey('rekey-2-closed', { current: e1, next: EPOCH_2, commit: true, closed: true })

// The requester's device credential, signed deterministically.
const credential = await createDeviceCredential({
  identity: {
    pubkey: REQUESTER,
    async signEvent(unsigned) {
      return finalizeDeterministic(unsigned, REQUESTER_SK, r('credential/aux'))
    },
  },
  devicePubkey: REQUESTER_DEVICE,
  roomId,
  expiresAt: NOW + 3600,
  now: () => NOW,
})

const request = recorded(['request/body', 'request/aux'], () =>
  encodeMemberEpochRequest({
    roomId,
    authority: AUTHORITY,
    deviceSk: REQUESTER_DEVICE_SK,
    roomKey,
    credential,
    have: 0,
    now: NOW,
  }),
)

function grant(label, epochs, rekeys) {
  return {
    epochs: epochs.map((e) => ({ epoch: e.epoch, secretHex: hex(e.secret) })),
    ...recorded([`${label}/body`, `${label}/aux`], () =>
    encodeMemberEpochGrant({
      roomId,
      deviceSk: MEMBER_DEVICE_SK,
      device: REQUESTER_DEVICE,
      request: request.event.id,
      epochs,
      rekeys: rekeys.map((x) => x.event),
      now: NOW,
    }),
  ),
  }
}

const decodeInput = {
  roomId,
  authority: AUTHORITY,
  requesterDeviceSkHex: hex(REQUESTER_DEVICE_SK),
  requests: [request.event.id],
  current: { epoch: 0, keyHex: hex(e0.key) },
  participant: REQUESTER,
  removed: [],
  now: NOW,
}

function decodeResult(g, extra = {}) {
  const input = { ...decodeInput, ...extra }
  const out = decodeMemberEpochGrant(g.event, {
    roomId: input.roomId,
    authority: input.authority,
    deviceSk: REQUESTER_DEVICE_SK,
    requests: new Set(input.requests),
    current: { epoch: input.current.epoch, id: '', key: Buffer.from(input.current.keyHex, 'hex') },
    participant: input.participant,
    removed: input.removed,
    ...(input.expected !== undefined ? { expected: input.expected } : {}),
    now: input.now,
  })
  return { input, result: out && { epoch: out.epoch.epoch, secretHex: hex(out.epoch.secret), removed: out.removed, from: out.from } }
}

function grantVector(name, kind, note, g, rekeys, extra = {}) {
  const { input, result } = decodeResult(g, extra)
  if ((kind === 'positive') !== (result !== null)) throw new Error(`vector ${name}: expected ${kind}, got ${JSON.stringify(result)}`)
  return {
    name,
    kind,
    note,
    input: { ...input, memberDeviceSkHex: hex(MEMBER_DEVICE_SK), grant: g, rekeys },
    output: { result },
  }
}

const accepted = grant('grant-accepted', [EPOCH_1, EPOCH_2], [rekey1Legacy, rekey2])
const forgedTop = grant('grant-forged-top', [EPOCH_1, { epoch: 2, secret: FORGED_SECRET }], [rekey1Legacy, rekey2])
const forgedMiddle = grant('grant-forged-middle', [{ epoch: 1, secret: FORGED_SECRET }, EPOCH_2], [rekey1Legacy, rekey2])
const legacyTop = grant('grant-legacy-top', [EPOCH_1], [rekey1Legacy])
const removesRequester = grant('grant-removes-requester', [EPOCH_1, EPOCH_2], [rekey1Committed, rekey2RemovesRequester])
const closedRoom = grant('grant-closed-room', [EPOCH_1, EPOCH_2], [rekey1Committed, rekey2Closed])
const shortOfExpected = grant('grant-short-of-expected', [EPOCH_1], [rekey1Committed])

const decodedRequest = decodeMemberEpochRequest(request.event, { roomId, authority: AUTHORITY, roomKey, now: NOW })
const evidence2 = readRekeyEvidence(rekey2.event, { roomId, authority: AUTHORITY, previous: e1 })
const evidence1 = readRekeyEvidence(rekey1Legacy.event, { roomId, authority: AUTHORITY, previous: e0 })

const vectors = [
  {
    name: 'epoch-commitment',
    kind: 'positive',
    note: 'HMAC-SHA256(key = the epoch secret, message = "kithmoot/v1/epoch-commit:" + roomId (lower-case hex) + ":" + epoch (decimal)), as lower-case hex. Written by the authority into the encrypted rekey body as `commit` when asked (`encodeRekeyEvent({ commit: true })`).',
    input: { roomId, epoch: 2, secretHex: hex(EPOCH_2.secret) },
    output: { commitHex: epochCommitment(roomId, 2, EPOCH_2.secret) },
  },
  {
    name: 'member-request-key',
    kind: 'positive',
    note: 'The key a member epoch request body is NIP-44-sealed under (used directly as the NIP-44 v2 conversation key): HKDF-SHA256(ikm = the epoch-0 room key, no salt, info = "kithmoot/v1/member-epoch-request-key", 32).',
    input: { roomKeyHex: hex(roomKey) },
    output: { keyHex: hex(deriveMemberEpochRequestKey(roomKey)) },
  },
  {
    name: 'rekey-with-commitment',
    kind: 'positive',
    note: 'A kind-1462 rekey from epoch 1 to epoch 2 that removes one participant and carries the commitment. Body key order: v, epoch, removed, commit, keys (`by` and `closed` would sit before `commit`). `randomHex` lists the encoder\'s random draws in order: the seal nonce for each recipient, the body nonce, the signature aux-rand. Read with epoch 1\'s key (`previousKeyHex`) by anybody at epoch 1, with or without a seal of their own.',
    input: { roomId, authority: AUTHORITY, previousEpoch: 1, previousSecretHex: hex(EPOCH_1.secret), previousKeyHex: hex(e1.key), next: { epoch: 2, secretHex: hex(EPOCH_2.secret) }, recipients: [MEMBER_DEVICE], removed: [GONE], authoritySkHex: hex(AUTHORITY_SK), createdAt: NOW - 998, ...rekey2 },
    output: { evidence: evidence2 },
  },
  {
    name: 'rekey-without-commitment',
    kind: 'positive',
    note: 'The same encoder without `commit`: byte-identical in shape to every rekey before this existed (body keys v, epoch, removed, keys). Readable as evidence, with no commitment - so its epoch can be vouched for only by a later rekey decrypting under it, never on its own.',
    input: { roomId, authority: AUTHORITY, previousEpoch: 0, previousKeyHex: hex(e0.key), next: { epoch: 1, secretHex: hex(EPOCH_1.secret) }, recipients: [MEMBER_DEVICE], removed: [], authoritySkHex: hex(AUTHORITY_SK), createdAt: NOW - 999, ...rekey1Legacy },
    output: { evidence: evidence1 },
  },
  {
    name: 'member-request',
    kind: 'positive',
    note: 'Kind 20471, tags [["d", roomId]], signed by the asking device. Body (NIP-44 under the member request key): {"v":1,"credential":<device credential>,"admission":<epochRequestAdmission, exactly as the authority desk checks it>,"have":<the asker\'s epoch>}. `randomHex`: body nonce, aux-rand.',
    input: { roomId, authority: AUTHORITY, roomKeyHex: hex(roomKey), requesterDeviceSkHex: hex(REQUESTER_DEVICE_SK), credential: JSON.parse(JSON.stringify(credential)), have: 0, now: NOW, ...request },
    output: { decoded: decodedRequest },
  },
  grantVector(
    'member-grant-accepted',
    'positive',
    'Kind 20472, tags [["d", roomId], ["p", asking device]], signed by the answering member\'s device and NIP-44-sealed to the asking device. Body: {"v":1,"request","epoch","secrets":[base64url, epochs have+1..epoch],"rekeys":[the authority\'s rekey events, same order]}. The asker, at epoch 0, checks: each rekey is the authority\'s, for the next epoch, and decrypts under the key of the epoch before it (epoch 1\'s legacy rekey under its own epoch-0 key; epoch 2\'s under the key derived from the offered epoch-1 secret, which proves that secret); the last rekey carries a commitment equal to epochCommitment(roomId, 2, offered epoch-2 secret); nothing in the chain closes the room or removes the asker. `removed` is the asker\'s known set plus the chain\'s removals.',
    accepted,
    [rekey1Legacy, rekey2],
  ),
  grantVector('member-grant-forged-top-secret', 'negative', 'The same chain with a different epoch-2 secret: its commitment does not match, so the grant is refused (null).', forgedTop, [rekey1Legacy, rekey2]),
  grantVector('member-grant-forged-middle-secret', 'negative', 'A different epoch-1 secret: epoch 2\'s rekey does not decrypt under the key it derives (NIP-44\'s MAC fails), so the grant is refused (null).', forgedMiddle, [rekey1Legacy, rekey2]),
  grantVector('member-grant-legacy-top', 'negative', 'A chain whose last rekey has no commitment: nothing vouches for the last secret, so a member cannot hand that epoch on. Refused (null); the asker falls back to the authority.', legacyTop, [rekey1Legacy]),
  grantVector('member-grant-removes-requester', 'negative', 'The authority\'s rekey to epoch 2 removes the asking participant: refused (null) even though every secret checks out.', removesRequester, [rekey1Committed, rekey2RemovesRequester]),
  grantVector('member-grant-closed-room', 'negative', 'The authority\'s rekey to epoch 2 closes the room: refused (null).', closedRoom, [rekey1Committed, rekey2Closed]),
  grantVector('member-grant-short-of-expected', 'negative', 'A valid chain to epoch 1 when the asker has seen an authority-signed rekey to epoch 2 (`expected`): refused (null), so a member removed at epoch 2 cannot hold the asker on epoch 1.', shortOfExpected, [rekey1Committed], { expected: 2 }),
]

const doc = {
  protocolVersion: 'kithmoot/v1',
  generatedBy: 'scripts/generate-member-epoch.mjs (forgesworn/fold-kit)',
  nostrToolsVersion,
  groups: { memberEpoch: vectors },
}

writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n')
console.log(`generate-member-epoch: wrote ${outPath} (${vectors.length} vectors)`)
