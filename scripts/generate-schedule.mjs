#!/usr/bin/env node
// Known-answer vectors for scheduled rekeys and the history window (the
// `scheduled` marker in `encodeRekeyEvent`, `HISTORY_WINDOW_SECONDS`,
// `MAX_HISTORY_EPOCHS`, `epochsInWindow`, and `passed` in `encodeEpochGrant`).
// See docs/scheduled-rekey.md.
//
// Written in KithMoot's vector format (`protocolVersion`, `groups`, and per
// vector `name`/`kind`/`note`/`input`/`output`), like the seal vectors, so the
// file can be copied verbatim into KithMoot's `vectors/` and from there into
// KithMoot Android's. Every input is a fixed labelled value from
// `vectors/lib/determinism.mjs`, and every random draw a real encoder makes is
// recorded beside the event it went into, in draw order. The events no
// correct encoder writes (a marked removal, an over-long window) are built by
// hand from a recorded body, nonce and aux-rand.
//
// Run after `npm run build`: `npm run generate-schedule`. Verified against
// `src/` directly by `vectors/verify-schedule.test.ts`.
import { writeFileSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bytesToHex } from '@noble/hashes/utils'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { getPublicKey } from 'nostr-tools/pure'
import { seed32, deriveSecretKey, finalizeDeterministic, withStubbedRandomness } from '../vectors/lib/determinism.mjs'
import {
  KINDS,
  HISTORY_WINDOW_SECONDS,
  MAX_HISTORY_EPOCHS,
  deriveRoom,
  deriveEpoch,
  epochsInWindow,
  epochCommitment,
  encodeRekeyEvent,
  decodeRekeyEvent,
  readRekeyEvidence,
  encodeEpochGrant,
  decodeEpochGrant,
} from '../dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const outPath = join(here, '..', 'vectors', 'schedule-vectors.json')
const nostrToolsVersion = JSON.parse(readFileSync(join(here, '..', 'node_modules', 'nostr-tools', 'package.json'), 'utf8')).version

// --- Fixed inputs ------------------------------------------------------------

const NOW = 1_800_000_000
const DAY = 86_400
const ROOM_SECRET = seed32('schedule/room-secret')
const { roomId } = deriveRoom(ROOM_SECRET)
const AUTHORITY_SK = deriveSecretKey('schedule/authority')
const AUTHORITY = getPublicKey(AUTHORITY_SK)
const DEVICE_SK = deriveSecretKey('schedule/device')
const DEVICE = getPublicKey(DEVICE_SK)
const MEMBER = getPublicKey(deriveSecretKey('schedule/member'))
const GONE = getPublicKey(deriveSecretKey('schedule/gone'))
const secretOf = (n) => seed32(`schedule/epoch-${n}-secret`)
const EPOCH_1 = { epoch: 1, secret: secretOf(1) }
const EPOCH_2 = { epoch: 2, secret: secretOf(2) }
const REQUEST = bytesToHex(seed32('schedule/request-id'))

const r = (label) => seed32(`schedule/random/${label}`)
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

/** An event signed by the authority around a body it was handed: what a
 *  broken or hostile encoder could publish. `randomHex`: the NIP-44 nonce,
 *  then the aux-rand. */
function handBuilt(label, { kind, tags, key, body }) {
  const bodyJson = JSON.stringify(body)
  const nonce = r(`${label}/body`)
  const aux = r(`${label}/aux`)
  const content = withStubbedRandomness([nonce], () => nip44.v2.encrypt(bodyJson, key))
  const event = finalizeDeterministic({ kind, created_at: NOW, tags, content }, AUTHORITY_SK, aux)
  return { event: plain(event), randomHex: [hex(nonce), hex(aux)], bodyJson }
}

const e1 = deriveEpoch(EPOCH_1)
const decryptBody = (event, key) => nip44.v2.decrypt(event.content, key)

// --- A scheduled rekey ---------------------------------------------------------

const scheduledOptions = {
  roomId,
  authoritySk: AUTHORITY_SK,
  current: e1,
  next: EPOCH_2,
  recipients: [DEVICE],
  removed: [],
  commit: true,
  members: [MEMBER],
  now: NOW,
}
const scheduled = recorded(['scheduled/seal-device', 'scheduled/body', 'scheduled/aux'], () =>
  encodeRekeyEvent({ ...scheduledOptions, scheduled: true }),
)
// The same rekey with the same draws and no marker: every rekey before 0.8.0.
const unflagged = recorded(['scheduled/seal-device', 'scheduled/body', 'scheduled/aux'], () => encodeRekeyEvent(scheduledOptions))

const notice = (n) =>
  n && {
    epoch: n.epoch,
    removed: n.removed,
    closed: n.closed,
    ...(n.scheduled ? { scheduled: true } : {}),
    ...(n.members ? { members: n.members } : {}),
    ...(n.secret ? { secretHex: hex(n.secret) } : {}),
    at: n.at,
  }
const readNotice = (event) => notice(decodeRekeyEvent(event, { roomId, authority: AUTHORITY, current: e1, deviceSk: DEVICE_SK }))
const readEvidence = (event) => readRekeyEvidence(event, { roomId, authority: AUTHORITY, previous: e1 })

// --- Contradictory rekeys --------------------------------------------------------

const rekeyTags = [['d', roomId], ['epoch', '2']]
const markedRemoval = handBuilt('contradictory-removal', {
  kind: KINDS.ROOM_REKEY,
  tags: rekeyTags,
  key: e1.key,
  body: { v: 1, epoch: 2, removed: [GONE], scheduled: true, keys: {} },
})
const markedClose = handBuilt('contradictory-close', {
  kind: KINDS.ROOM_REKEY,
  tags: rekeyTags,
  key: e1.key,
  body: { v: 1, epoch: 2, removed: [], closed: true, scheduled: true, keys: {} },
})
const refuses = (extra) => {
  try {
    encodeRekeyEvent({ ...scheduledOptions, scheduled: true, ...extra })
    return 'encoded'
  } catch {
    return 'refused'
  }
}

// --- A grant carrying the window -----------------------------------------------

const GRANTED = { epoch: 18, secret: secretOf(18) }
/** Epochs 2..17, left an hour after the one before: sixteen, the cap. */
const PASSED = Array.from({ length: 16 }, (_, i) => ({ epoch: i + 2, secret: secretOf(i + 2), leftAt: NOW - (16 - i) * 3600 }))
const passedHex = (list) => list.map((e) => ({ epoch: e.epoch, secretHex: hex(e.secret), leftAt: e.leftAt }))
const grantOptions = { roomId, authoritySk: AUTHORITY_SK, device: DEVICE, request: REQUEST, now: NOW, epoch: GRANTED, removed: [] }
const windowGrant = recorded(['grant-window/body', 'grant-window/aux'], () => encodeEpochGrant({ ...grantOptions, passed: PASSED }))
const grantKey = nip44.v2.utils.getConversationKey(AUTHORITY_SK, DEVICE)
const seventeen = (() => {
  try {
    encodeEpochGrant({ ...grantOptions, passed: [{ epoch: 1, secret: EPOCH_1.secret, leftAt: NOW - 17 * 3600 }, ...PASSED] })
    return 'encoded'
  } catch {
    return 'refused'
  }
})()

const readGrant = (event) => {
  const g = decodeEpochGrant(event, { roomId, authority: AUTHORITY, deviceSk: DEVICE_SK, request: REQUEST, now: NOW })
  return (
    g && {
      epoch: g.epoch.epoch,
      secretHex: hex(g.epoch.secret),
      removed: g.removed,
      ...(g.passed ? { passed: passedHex(g.passed) } : {}),
    }
  )
}

const wire = (e) => ({ epoch: e.epoch, secret: base64urlnopad.encode(e.secret), left: e.leftAt })
const grantBody = (passed) => ({ v: 1, request: REQUEST, epoch: 18, secret: base64urlnopad.encode(GRANTED.secret), removed: [], passed })
const grantTags = [['d', roomId], ['p', DEVICE]]
const malformed = {
  overCap: handBuilt('grant-over-cap', {
    kind: KINDS.EPOCH_GRANT,
    tags: grantTags,
    key: grantKey,
    body: grantBody([wire({ epoch: 1, secret: EPOCH_1.secret, leftAt: NOW - 17 * 3600 }), ...PASSED.map(wire)]),
  }),
  unsorted: handBuilt('grant-unsorted', { kind: KINDS.EPOCH_GRANT, tags: grantTags, key: grantKey, body: grantBody([wire(PASSED[1]), wire(PASSED[0])]) }),
  epochZero: handBuilt('grant-epoch-zero', {
    kind: KINDS.EPOCH_GRANT,
    tags: grantTags,
    key: grantKey,
    body: grantBody([{ epoch: 0, secret: base64urlnopad.encode(ROOM_SECRET), left: NOW - 20 * 3600 }, wire(PASSED[0])]),
  }),
}

/**
 * The authority's grant as 0.7.0's `decodeEpochGrant` reads it, once the
 * envelope checks (unchanged since) have passed: its body handling, copied
 * line for line, with the device key as the only key tried. It builds its
 * answer from named fields, so `passed` is never seen.
 */
function readGrantAs070(event) {
  const body = JSON.parse(nip44.v2.decrypt(event.content, nip44.v2.utils.getConversationKey(DEVICE_SK, event.pubkey)))
  if (body.v !== 1 || typeof body.request !== 'string' || body.request.toLowerCase() !== REQUEST) return null
  if (body.refused === 'removed' || body.refused === 'closed' || body.refused === 'unknown') return { refused: body.refused }
  if (!Number.isSafeInteger(body.epoch) || body.epoch < 0 || body.epoch > 1_000_000) return null
  const removed = Array.isArray(body.removed)
    ? [...new Set(body.removed.filter((p) => typeof p === 'string' && /^[0-9a-f]{64}$/i.test(p)).map((p) => p.toLowerCase()))].sort()
    : []
  if (body.epoch === 0) return { epoch: 0, removed }
  if (typeof body.secret !== 'string') return null
  const secret = base64urlnopad.decode(body.secret)
  if (secret.length !== 32) return null
  return { epoch: body.epoch, secretHex: hex(secret), removed }
}

// --- The history window --------------------------------------------------------

const windowCases = [
  {
    name: 'edge',
    now: NOW,
    left: [
      { epoch: 1, leftAt: NOW - HISTORY_WINDOW_SECONDS - 1 },
      { epoch: 2, leftAt: NOW - HISTORY_WINDOW_SECONDS },
      { epoch: 3, leftAt: NOW - DAY },
    ],
  },
  { name: 'cap', now: NOW, left: Array.from({ length: 20 }, (_, i) => ({ epoch: i + 1, leftAt: NOW - (20 - i) * 3600 })) },
  { name: 'weekly', now: NOW, left: Array.from({ length: 10 }, (_, i) => ({ epoch: i + 1, leftAt: NOW - (10 - i) * 7 * DAY })) },
  {
    name: 'unsorted-and-doubled',
    now: NOW,
    left: [
      { epoch: 2, leftAt: NOW - 100 },
      { epoch: 5, leftAt: NOW - 50 },
      { epoch: 3, leftAt: NOW - 31 * DAY },
      { epoch: 5, leftAt: NOW - 10 },
      { epoch: 4, leftAt: NOW - 60 },
    ],
  },
  { name: 'empty', now: NOW, left: [] },
]

// --- Vectors -----------------------------------------------------------------

const vectors = [
  {
    name: 'scheduled-rekey',
    kind: 'positive',
    note: 'A kind-1462 rekey from epoch 1 to 2 that removes nobody, carries the member list and the epoch commitment, and is marked `"scheduled": true` inside its encrypted body (after `closed`\'s place, before `commit`), so a relay cannot tell it from a removal. Readers report `scheduled` only when `removed` is empty and the room is not closed. Read with epoch 1\'s key (`readRekeyEvidence`), it checks out like any other rekey, so a member grant\'s chain runs through it unbroken. `randomHex`: the seal nonce for DEVICE, the body nonce, the aux-rand. `unflagged` is the same rekey with the same draws and no marker, which is every rekey before 0.8.0: its body is `bodyJson` without `"scheduled":true,`.',
    input: {
      roomId, authority: AUTHORITY, authoritySkHex: hex(AUTHORITY_SK), previous: { epoch: 1, secretHex: hex(EPOCH_1.secret) },
      next: { epoch: 2, secretHex: hex(EPOCH_2.secret) }, recipients: [DEVICE], members: [MEMBER], deviceSkHex: hex(DEVICE_SK), createdAt: NOW,
      ...scheduled, unflagged,
    },
    output: {
      bodyJson: decryptBody(scheduled.event, e1.key),
      unflaggedBodyJson: decryptBody(unflagged.event, e1.key),
      notice: readNotice(scheduled.event),
      evidence: readEvidence(scheduled.event),
      commit: epochCommitment(roomId, 2, EPOCH_2.secret),
      unflaggedNotice: readNotice(unflagged.event),
    },
  },
  {
    name: 'scheduled-rekey-contradictory',
    kind: 'negative',
    note: 'Two rekeys from epoch 1 to 2, signed by the authority, whose bodies carry the marker beside something that is never quiet: a removal (`withRemoval`) and a close (`withClose`). The encoder refuses both combinations, so these are built by hand (`bodyJson`, then `randomHex`: the body nonce, the aux-rand). A reader still reads each rekey, and reports it as not scheduled, so the removal or the close is announced.',
    input: { roomId, authority: AUTHORITY, previous: { epoch: 1, secretHex: hex(EPOCH_1.secret) }, deviceSkHex: hex(DEVICE_SK), withRemoval: markedRemoval, withClose: markedClose },
    output: {
      encoder: { withRemoval: refuses({ removed: [GONE] }), withClose: refuses({ closed: true }) },
      withRemoval: { notice: readNotice(markedRemoval.event), evidence: readEvidence(markedRemoval.event) },
      withClose: { notice: readNotice(markedClose.event), evidence: readEvidence(markedClose.event) },
    },
  },
  {
    name: 'epoch-grant-window',
    kind: 'positive',
    note: `A kind-20469 grant of epoch 18 that carries the window: \`passed\`, epochs 2 to 17 oldest first, each \`{ epoch, secret (base64url), left (unix seconds) }\`. ${MAX_HISTORY_EPOCHS} is the cap: the encoder refuses a 17th (\`seventeen\`). Epoch 0 is never carried (its secret is the room secret), nor anything at or above the granted epoch. A reader takes \`passed\` only in that exact form (strictly increasing, each in [1, epoch), at most ${MAX_HISTORY_EPOCHS}, 32-byte secrets, a non-negative integer \`left\`); anything else drops the field and keeps the grant (\`malformed\`: seventeen entries, two out of order, one for epoch 0, each built by hand). \`randomHex\`: the body nonce, the aux-rand.`,
    input: {
      roomId, authority: AUTHORITY, authoritySkHex: hex(AUTHORITY_SK), deviceSkHex: hex(DEVICE_SK), request: REQUEST, now: NOW,
      epoch: { epoch: 18, secretHex: hex(GRANTED.secret) }, passed: passedHex(PASSED), ...windowGrant, malformed,
    },
    output: {
      bodyJson: nip44.v2.decrypt(windowGrant.event.content, grantKey),
      grant: readGrant(windowGrant.event),
      seventeen,
      malformed: Object.fromEntries(Object.entries(malformed).map(([k, v]) => [k, readGrant(v.event)])),
    },
  },
  {
    name: 'epoch-grant-window-old-reader',
    kind: 'positive',
    note: 'The `epoch-grant-window` grant read as 0.7.0 (and KithMoot Android 0.6.57) reads it: its body is read by named fields, so `passed` is ignored and the reader gets the current epoch, as from any grant before 0.8.0. A device on an old release is no worse off; it reads the window only once it updates.',
    input: { roomId, authority: AUTHORITY, deviceSkHex: hex(DEVICE_SK), request: REQUEST, now: NOW, event: windowGrant.event },
    output: { oldReader: readGrantAs070(windowGrant.event) },
  },
  {
    name: 'history-window',
    kind: 'positive',
    note: `\`epochsInWindow(left, now)\`: the left epochs still read, those left within HISTORY_WINDOW_SECONDS (${HISTORY_WINDOW_SECONDS}, 30 days; one left exactly that long ago is kept), newest first by epoch, the first given of a doubled epoch, at most MAX_HISTORY_EPOCHS (${MAX_HISTORY_EPOCHS}). Each case lists \`{ epoch, leftAt }\` in and out.`,
    input: { windowSeconds: HISTORY_WINDOW_SECONDS, maxEpochs: MAX_HISTORY_EPOCHS, cases: windowCases },
    output: { cases: windowCases.map((c) => ({ name: c.name, kept: epochsInWindow(c.left, c.now) })) },
  },
]

// --- Self-checks ------------------------------------------------------------------

const v = (name) => vectors.find((x) => x.name === name)
const s = v('scheduled-rekey').output
if (!s.notice?.scheduled || !s.notice.secretHex || !s.evidence?.scheduled || s.evidence.commit !== s.commit) throw new Error('scheduled-rekey does not read as scheduled')
if (s.unflaggedNotice.scheduled || s.unflaggedBodyJson !== s.bodyJson.replace('"scheduled":true,', '')) throw new Error('the unflagged rekey is not the 0.7.0 body')
const c = v('scheduled-rekey-contradictory').output
if (c.encoder.withRemoval !== 'refused' || c.encoder.withClose !== 'refused') throw new Error('the encoder marked a removal or a close')
for (const k of ['withRemoval', 'withClose']) if (!c[k].notice || c[k].notice.scheduled || !c[k].evidence || c[k].evidence.scheduled) throw new Error(`${k} read as scheduled`)
const g = v('epoch-grant-window').output
if (g.grant?.passed?.length !== 16 || g.seventeen !== 'refused') throw new Error('epoch-grant-window does not carry 16 and refuse 17')
for (const [k, read] of Object.entries(g.malformed)) if (!read || read.passed || read.epoch !== 18) throw new Error(`malformed ${k} did not keep the grant and drop the field`)
const old = v('epoch-grant-window-old-reader').output.oldReader
if (JSON.stringify(old) !== JSON.stringify({ epoch: 18, secretHex: g.grant.secretHex, removed: [] })) throw new Error('the old reader does not get the current epoch')

const doc = {
  protocolVersion: 'kithmoot/v1',
  generatedBy: 'scripts/generate-schedule.mjs (forgesworn/fold-kit)',
  nostrToolsVersion,
  groups: { schedule: vectors },
}

writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n')
console.log(`generate-schedule: wrote ${outPath} (${vectors.length} vectors)`)
