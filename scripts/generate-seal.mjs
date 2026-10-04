#!/usr/bin/env node
// Known-answer vectors for seal keys (src/seal.ts, the `seal` option on
// `createDeviceCredential`, and sealing in `encodeRekeyEvent`,
// `encodeEpochGrant` and `encodeMemberEpochGrant`). See docs/seal-key.md.
//
// Written in KithMoot's vector format (`protocolVersion`, `groups`, and per
// vector `name`/`kind`/`note`/`input`/`output`), like the member-epoch
// vectors, so the file can be copied verbatim into KithMoot's `vectors/` and
// from there into KithMoot Android's. Every input is a fixed labelled value
// from `vectors/lib/determinism.mjs`, and every random draw a real encoder
// makes is recorded beside the event it went into, in draw order.
//
// Run after `npm run build`: `npm run generate-seal`. Verified against
// `src/` directly by `vectors/verify-seal.test.ts`.
import { writeFileSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bytesToHex } from '@noble/hashes/utils'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { schnorr } from '@noble/curves/secp256k1.js'
import { getPublicKey } from 'nostr-tools/pure'
import { seed32, deriveSecretKey, finalizeDeterministic, withStubbedRandomness } from '../vectors/lib/determinism.mjs'
import {
  KINDS,
  deriveRoom,
  deriveEpoch,
  createDeviceCredential,
  credentialSeal,
  newerCredential,
  sealTarget,
  sealCredential,
  encodeRekeyEvent,
  decodeRekeyEvent,
  encodeEpochRequest,
  decodeEpochRequest,
  encodeEpochGrant,
  decodeEpochGrant,
  encodeMemberEpochGrant,
  decodeMemberEpochGrant,
} from '../dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const outPath = join(here, '..', 'vectors', 'seal-vectors.json')
const nostrToolsVersion = JSON.parse(readFileSync(join(here, '..', 'node_modules', 'nostr-tools', 'package.json'), 'utf8')).version

// --- Fixed inputs ------------------------------------------------------------

const NOW = 1_800_000_000
const ROOM_SECRET = seed32('seal/room-secret')
const { roomId, roomKey } = deriveRoom(ROOM_SECRET)
const AUTHORITY_SK = deriveSecretKey('seal/authority')
const AUTHORITY = getPublicKey(AUTHORITY_SK)
const PARTICIPANT_SK = deriveSecretKey('seal/participant')
const PARTICIPANT = getPublicKey(PARTICIPANT_SK)
const DEVICE_SK = deriveSecretKey('seal/device')
const DEVICE = getPublicKey(DEVICE_SK)
const BARE_DEVICE_SK = deriveSecretKey('seal/bare-device')
const BARE_DEVICE = getPublicKey(BARE_DEVICE_SK)
/** The seal key of the credential live when the device was copied. */
const COPIED_SEAL_SK = deriveSecretKey('seal/seal-copied')
const COPIED_SEAL = getPublicKey(COPIED_SEAL_SK)
/** The seal key the device minted at its next renewal. */
const RENEWED_SEAL_SK = deriveSecretKey('seal/seal-renewed')
const RENEWED_SEAL = getPublicKey(RENEWED_SEAL_SK)
/** x = 5 has no square root mod p: 32-byte hex, but no point. */
const OFF_CURVE = '0'.repeat(63) + '5'
const EPOCH_1 = { epoch: 1, secret: seed32('seal/epoch-1-secret') }
const EPOCH_2 = { epoch: 2, secret: seed32('seal/epoch-2-secret') }

const r = (label) => seed32(`seal/random/${label}`)
const hex = bytesToHex

function plain(event) {
  const { id, pubkey, created_at, kind, tags, content, sig } = event
  return { id, pubkey, created_at, kind, tags, content, sig }
}

function recorded(labels, fn) {
  const draws = labels.map(r)
  const event = withStubbedRandomness(draws, fn)
  return { event: plain(event), randomHex: draws.map(hex) }
}

const deterministicParticipant = (label) => ({
  pubkey: PARTICIPANT,
  async signEvent(unsigned) {
    return finalizeDeterministic(unsigned, PARTICIPANT_SK, r(`${label}/aux`))
  },
})

async function credential(label, { seal, createdAt, expiresAt }) {
  return plain(
    await createDeviceCredential({
      identity: deterministicParticipant(label),
      devicePubkey: DEVICE,
      roomId,
      expiresAt,
      ...(seal !== undefined ? { seal } : {}),
      now: () => createdAt,
    }),
  )
}

/** Signed by the participant with tags no correct minter writes. */
function oddCredential(label, extraTags) {
  return finalizeDeterministic(
    {
      kind: KINDS.CREDENTIAL,
      created_at: NOW,
      tags: [['d', roomId], ['device', DEVICE], ['expiration', String(NOW + 43_200)], ...extraTags],
      content: '',
    },
    PARTICIPANT_SK,
    r(`${label}/aux`),
  )
}

// The incident: copied at NOW - 6 h, under a credential that runs to NOW + 6 h;
// renewed at NOW, under a fresh seal key.
const copied = await credential('credential-copied', { seal: COPIED_SEAL, createdAt: NOW - 21_600, expiresAt: NOW + 21_600 })
const renewed = await credential('credential-renewed', { seal: RENEWED_SEAL, createdAt: NOW, expiresAt: NOW + 43_200 })
const unsealed = await credential('credential-renewed', { createdAt: NOW, expiresAt: NOW + 43_200 })
const doubled = oddCredential('credential-doubled', [['seal', RENEWED_SEAL], ['seal', COPIED_SEAL]])
const offCurve = oddCredential('credential-off-curve', [['seal', OFF_CURVE]])

const e0 = deriveEpoch({ epoch: 0, secret: ROOM_SECRET })

// --- Rekey -------------------------------------------------------------------

const rekey = recorded(['rekey/seal-device', 'rekey/seal-bare', 'rekey/body', 'rekey/aux'], () =>
  encodeRekeyEvent({
    roomId,
    authoritySk: AUTHORITY_SK,
    current: e0,
    next: EPOCH_1,
    recipients: [{ device: DEVICE, credential: renewed }, BARE_DEVICE],
    removed: [],
    now: NOW,
  }),
)

const readRekey = (deviceSk, sealSks, event = rekey.event) => {
  const notice = decodeRekeyEvent(event, { roomId, authority: AUTHORITY, current: e0, deviceSk, sealSks })
  return notice && { epoch: notice.epoch, ...(notice.secret ? { secretHex: hex(notice.secret) } : {}) }
}

// The same rekey, recipients given with credentials that name no seal key:
// byte-identical to one given bare devices.
const rekeyUnsealed = recorded(['rekey-unsealed/seal-device', 'rekey-unsealed/seal-bare', 'rekey-unsealed/body', 'rekey-unsealed/aux'], () =>
  encodeRekeyEvent({
    roomId,
    authoritySk: AUTHORITY_SK,
    current: e0,
    next: EPOCH_1,
    recipients: [{ device: DEVICE, credential: unsealed }, BARE_DEVICE],
    removed: [],
    now: NOW,
  }),
)

// --- The authority's grant (20469) --------------------------------------------

// The thief asks under the copied credential; the authority has seen the renewed one.
const request = recorded(['request/body', 'request/aux'], () =>
  encodeEpochRequest({ roomId, authority: AUTHORITY, deviceSk: DEVICE_SK, roomKey, credential: copied, now: NOW }),
)
const decodedRequest = decodeEpochRequest(request.event, { roomId, authoritySk: AUTHORITY_SK, roomKey, now: NOW })
const chosen = sealCredential(decodedRequest, copied, () => renewed, roomId, NOW)
if (chosen !== renewed) throw new Error('the desk should seal to the renewed credential')

const epochGrant = recorded(['grant/body', 'grant/aux'], () =>
  encodeEpochGrant({
    roomId,
    authoritySk: AUTHORITY_SK,
    device: DEVICE,
    request: request.event.id,
    now: NOW,
    epoch: EPOCH_2,
    removed: [],
    credential: chosen,
  }),
)
const readEpochGrant = (sealSks) => {
  const g = decodeEpochGrant(epochGrant.event, { roomId, authority: AUTHORITY, deviceSk: DEVICE_SK, sealSks, request: request.event.id, now: NOW })
  return g && { epoch: g.epoch.epoch, secretHex: hex(g.epoch.secret) }
}

// --- A member's grant (20472) -------------------------------------------------

const committedRekey = recorded(['committed-rekey/body', 'committed-rekey/aux'], () =>
  encodeRekeyEvent({ roomId, authoritySk: AUTHORITY_SK, current: e0, next: EPOCH_1, recipients: [], removed: [], commit: true, now: NOW - 10 }),
)
const MEMBER_REQUEST = hex(seed32('seal/member-request-id'))
const seed48 = (label) => hkdf(sha256, seed32(`seal/random/${label}`), undefined, 'seal/seed48', 48)
const signerDraw = seed48('member-grant/signer')
const signerSk = schnorr.utils.randomSecretKey(signerDraw)
const memberDraws = [signerDraw, r('member-grant/body'), r('member-grant/aux')]
const memberGrant = plain(
  withStubbedRandomness(memberDraws, () =>
    encodeMemberEpochGrant({
      roomId,
      device: DEVICE,
      request: MEMBER_REQUEST,
      epochs: [EPOCH_1],
      rekeys: [committedRekey.event],
      credential: renewed,
      now: NOW,
    }),
  ),
)
if (memberGrant.pubkey !== getPublicKey(signerSk)) throw new Error('the member grant was not signed by the recorded one-time key')
const readMemberGrant = (sealSks) => {
  const g = decodeMemberEpochGrant(memberGrant, {
    roomId,
    authority: AUTHORITY,
    deviceSk: DEVICE_SK,
    sealSks,
    requests: new Set([MEMBER_REQUEST]),
    current: e0,
    participant: PARTICIPANT,
    now: NOW,
  })
  return g && { epoch: g.epoch.epoch, secretHex: hex(g.epoch.secret) }
}

// --- Vectors -----------------------------------------------------------------

const seal = (c) => {
  const s = credentialSeal(c)
  return s === undefined ? 'none' : s === null ? 'unusable' : s
}

const healed = (fn) => ({ renewedDevice: fn([RENEWED_SEAL_SK, COPIED_SEAL_SK]), thief: fn([COPIED_SEAL_SK]) })

const vectors = [
  {
    name: 'credential-seal-key',
    kind: 'positive',
    note: 'A kind-20460 room credential carrying the device\'s seal key: tags d, device, expiration (then scope and label when present), then ["seal", x-only pubkey, lower-case hex] last, all under the participant\'s signature. A seal key must lift to a point on secp256k1. Rekeys and epoch grants for this device are NIP-44-sealed to it instead of the device key. The device mints a fresh one at every renewal and keeps the secrets as it keeps its device key: healing needs only that each new one is fresh.',
    input: { roomId, participantSkHex: hex(PARTICIPANT_SK), device: DEVICE, sealSkHex: hex(RENEWED_SEAL_SK), createdAt: NOW, expiresAt: NOW + 43_200, credential: renewed },
    output: { seal: seal(renewed), sealTarget: sealTarget(DEVICE, renewed) },
  },
  {
    name: 'credential-without-seal',
    kind: 'positive',
    note: 'The same credential minted without a seal key: no seal tag, and its tags are exactly the renewed credential\'s without the last, which is every credential minted before seal keys existed. Everything is sealed to the device key, as before.',
    input: { roomId, participantSkHex: hex(PARTICIPANT_SK), device: DEVICE, createdAt: NOW, expiresAt: NOW + 43_200, credential: unsealed },
    output: { seal: seal(unsealed), sealTarget: sealTarget(DEVICE, unsealed) },
  },
  {
    name: 'credential-seal-doubled',
    kind: 'negative',
    note: 'Two seal tags. Only the participant could have signed this, so it is a broken minter, not an attack: the seal is "unusable", and a sender seals to the device key rather than failing the whole rekey.',
    input: { credential: doubled },
    output: { seal: seal(doubled), sealTarget: sealTarget(DEVICE, doubled) },
  },
  {
    name: 'credential-seal-off-curve',
    kind: 'negative',
    note: 'A seal tag of 32-byte hex that is not the x coordinate of any point (x = 5): "unusable", sealed to the device key.',
    input: { credential: offCurve },
    output: { seal: seal(offCurve), sealTarget: sealTarget(DEVICE, offCurve) },
  },
  {
    name: 'newer-credential',
    kind: 'positive',
    note: 'Which of two credentials for one device is newer: the later expiration, then the later created_at; a tie keeps the first. Expiration leads because some remote signers restamp created_at. A desk seals to the newer of the credential a request carries and the newest it has seen in the roster.',
    input: { a: copied, b: renewed },
    output: { newer: newerCredential(copied, renewed) === renewed ? 'b' : 'a' },
  },
  {
    name: 'rekey-seal',
    kind: 'positive',
    note: 'A kind-1462 rekey from epoch 0 to 1 for two devices: DEVICE, given with its renewed credential, sealed to that credential\'s seal key; BARE_DEVICE, given bare, sealed to its device key. The keys map is keyed by device either way. `randomHex`: one seal nonce per recipient in order, the body nonce, the signature aux-rand. A reader tries each live seal key, then its device key; a copy none of them opens reads as no copy (the rekey is still read, without a secret), and the device asks for the epoch. `thief` holds the device key and the copied credential\'s seal key only.',
    input: {
      roomId, authority: AUTHORITY, authoritySkHex: hex(AUTHORITY_SK), previousKeyHex: hex(e0.key), next: { epoch: 1, secretHex: hex(EPOCH_1.secret) },
      recipients: [{ device: DEVICE, credential: renewed }, BARE_DEVICE], deviceSkHex: hex(DEVICE_SK), bareDeviceSkHex: hex(BARE_DEVICE_SK),
      renewedSealSkHex: hex(RENEWED_SEAL_SK), copiedSealSkHex: hex(COPIED_SEAL_SK), createdAt: NOW, ...rekey,
    },
    output: {
      sealedTo: { [DEVICE]: RENEWED_SEAL, [BARE_DEVICE]: BARE_DEVICE },
      ...healed((sks) => readRekey(DEVICE_SK, sks)),
      bareDevice: readRekey(BARE_DEVICE_SK, []),
    },
  },
  {
    name: 'rekey-without-seal-keys',
    kind: 'positive',
    note: 'The same rekey with DEVICE given a credential that names no seal key: byte-identical to the event encoded with recipients [DEVICE, BARE_DEVICE] as bare strings and the same draws, which is every rekey before seal keys.',
    input: {
      roomId, authority: AUTHORITY, authoritySkHex: hex(AUTHORITY_SK), previousKeyHex: hex(e0.key), next: { epoch: 1, secretHex: hex(EPOCH_1.secret) },
      recipients: [{ device: DEVICE, credential: unsealed }, BARE_DEVICE], deviceSkHex: hex(DEVICE_SK), createdAt: NOW, ...rekeyUnsealed,
    },
    output: { device: readRekey(DEVICE_SK, [], rekeyUnsealed.event) },
  },
  {
    name: 'epoch-grant-seal',
    kind: 'positive',
    note: 'The thief replays the copied, still-live credential in a kind-20460 epoch request (`request`). The authority has seen the renewed one in the roster, so its kind-20469 grant is sealed to the renewed seal key: `sealCredential` picks the newer of the presented and the known credential, when the known one verifies for the same room, device and participant. `grant.randomHex`: body nonce, aux-rand. The renewed device opens it; the thief does not (null).',
    input: {
      roomId, authority: AUTHORITY, authoritySkHex: hex(AUTHORITY_SK), roomKeyHex: hex(roomKey), deviceSkHex: hex(DEVICE_SK), now: NOW,
      presented: copied, known: renewed, epoch: { epoch: 2, secretHex: hex(EPOCH_2.secret) },
      renewedSealSkHex: hex(RENEWED_SEAL_SK), copiedSealSkHex: hex(COPIED_SEAL_SK), request, grant: epochGrant,
    },
    output: { sealedTo: RENEWED_SEAL, ...healed(readEpochGrant) },
  },
  {
    name: 'member-grant-seal',
    kind: 'positive',
    note: 'A member\'s kind-20472 grant of epoch 1 (proven by the authority\'s committed rekey, `rekey`) to DEVICE, sealed from its one-time key to the renewed credential\'s seal key. `grant.randomHex`: the 48-byte seed for the one-time key (`signerSkHex`), body nonce, aux-rand. The renewed device opens it; the thief does not (null).',
    input: {
      roomId, authority: AUTHORITY, deviceSkHex: hex(DEVICE_SK), participant: PARTICIPANT, request: MEMBER_REQUEST, now: NOW,
      currentKeyHex: hex(e0.key), epoch: { epoch: 1, secretHex: hex(EPOCH_1.secret) }, credential: renewed, rekey: committedRekey,
      renewedSealSkHex: hex(RENEWED_SEAL_SK), copiedSealSkHex: hex(COPIED_SEAL_SK),
      grant: { event: memberGrant, randomHex: memberDraws.map(hex), signerSkHex: hex(signerSk) },
    },
    output: { sealedTo: RENEWED_SEAL, ...healed(readMemberGrant) },
  },
]

if (!vectors.find((v) => v.name === 'rekey-without-seal-keys').output.device?.secretHex) throw new Error('rekey-without-seal-keys: the device cannot read its own copy')
for (const v of vectors) {
  if (v.name === 'rekey-seal' && (v.output.thief?.secretHex || !v.output.renewedDevice?.secretHex)) throw new Error('rekey-seal does not heal')
  if (v.name.endsWith('grant-seal') && (v.output.thief !== null || v.output.renewedDevice === null)) throw new Error(`${v.name} does not heal`)
}

const doc = {
  protocolVersion: 'kithmoot/v1',
  generatedBy: 'scripts/generate-seal.mjs (forgesworn/fold-kit)',
  nostrToolsVersion,
  groups: { seal: vectors },
}

writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n')
console.log(`generate-seal: wrote ${outPath} (${vectors.length} vectors)`)
