#!/usr/bin/env node
// Known-answer vectors for self-destructing rooms: `destruct: true` in the
// group invitation body (`encodePersistentInvitation`), in an ended room's
// retirement (`encodeInvitationRetirement`), and in a closing rekey
// (`encodeRekeyEvent`). See docs/room-destruct.md.
//
// Written in KithMoot's vector format (`protocolVersion`, `groups`, and per
// vector `name`/`kind`/`note`/`input`/`output`), like the schedule vectors,
// so the file can be copied verbatim into KithMoot's `vectors/` and from
// there into KithMoot Android's. Every input is a fixed labelled value from
// `vectors/lib/determinism.mjs`, and every random draw a real encoder makes
// is recorded beside the event it went into, in draw order. The events no
// correct encoder writes (a malformed flag, a flag on an open rekey or a
// plain retirement) are built by hand from a recorded body, nonce and
// aux-rand.
//
// Each positive vector also records what a 0.8.0 reader makes of the new
// event (`oldReader`): that reader's body handling, copied line for line
// below, so a port can check it is no worse off on an old release.
//
// Run after `npm run build`: `npm run generate-destruct`. Verified against
// `src/` directly by `vectors/verify-destruct.test.ts`.
import { writeFileSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bytesToHex } from '@noble/hashes/utils'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { getPublicKey } from 'nostr-tools/pure'
import { seed32, deriveSecretKey, finalizeDeterministic, withStubbedRandomness } from '../vectors/lib/determinism.mjs'
import {
  KINDS,
  deriveRoom,
  deriveEpoch,
  deriveInvitationId,
  roomInvitation,
  isInvitationRelays,
  encodePersistentInvitation,
  decodePersistentInvitation,
  requestPersistentRoomAdmission,
  encodeInvitationRetirement,
  decodeInvitationRetirementNotice,
  encodeRekeyEvent,
  decodeRekeyEvent,
  readRekeyEvidence,
} from '../dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const outPath = join(here, '..', 'vectors', 'destruct-vectors.json')
const nostrToolsVersion = JSON.parse(readFileSync(join(here, '..', 'node_modules', 'nostr-tools', 'package.json'), 'utf8')).version

// --- Fixed inputs ------------------------------------------------------------

const NOW = 1_800_000_000
const ENDS = NOW + 86_400
const RELAYS = ['wss://relay.example.com/']
const INVITER_SK = deriveSecretKey('destruct/inviter')
const INVITER = getPublicKey(INVITER_SK)
const BEARER = seed32('destruct/bearer')
const INVITATION = roomInvitation(BEARER, INVITER, true)
const INVITATION_ID = deriveInvitationId(INVITATION)
const ROOM_SECRET = seed32('destruct/room-secret')
const { roomId } = deriveRoom(ROOM_SECRET)
const DEVICE_SK = deriveSecretKey('destruct/device')
const DEVICE = getPublicKey(DEVICE_SK)
const GONE = getPublicKey(deriveSecretKey('destruct/gone'))
const EPOCH_1 = { epoch: 1, secret: seed32('destruct/epoch-1-secret') }
const EPOCH_2 = { epoch: 2, secret: seed32('destruct/epoch-2-secret') }
const WELCOME_KEY = hkdf(sha256, BEARER, undefined, 'kithmoot/v3/group-invitation-key', 32)

const r = (label) => seed32(`destruct/random/${label}`)
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

/** An event signed by the inviter (the room's authority) around a body it
 *  was handed: what a broken or hostile encoder could publish. `randomHex`:
 *  the NIP-44 nonce, then the aux-rand; with no `key` the body is the plain
 *  content and only the aux-rand is drawn. */
function handBuilt(label, { kind, tags, key, body, createdAt = NOW }) {
  const bodyJson = JSON.stringify(body)
  const aux = r(`${label}/aux`)
  if (!key) {
    const event = finalizeDeterministic({ kind, created_at: createdAt, tags, content: bodyJson }, INVITER_SK, aux)
    return { event: plain(event), randomHex: [hex(aux)], bodyJson }
  }
  const nonce = r(`${label}/body`)
  const content = withStubbedRandomness([nonce], () => nip44.v2.encrypt(bodyJson, key))
  const event = finalizeDeterministic({ kind, created_at: createdAt, tags, content }, INVITER_SK, aux)
  return { event: plain(event), randomHex: [hex(nonce), hex(aux)], bodyJson }
}

const refused = (fn) => {
  try {
    fn()
    return 'encoded'
  } catch {
    return 'refused'
  }
}

// --- The 0.8.0 readers, copied line for line --------------------------------

/**
 * The group invitation as 0.8.0's `decodePersistentInvitation` reads it,
 * once the envelope checks (kind, signer, signature, `d` tag; unchanged)
 * have passed: its body handling, copied line for line. It builds its
 * answer from named fields, so `destruct` is never seen.
 */
function readInvitationAs080(event) {
  try {
    const body = JSON.parse(nip44.v2.decrypt(event.content, WELCOME_KEY))
    if (body.v !== 3 || typeof body.secret !== 'string') return null
    const secret = base64urlnopad.decode(body.secret)
    if (deriveRoom(secret).roomId !== body.room) return null
    const isRoomEnds = (value) => typeof value === 'number' && Number.isSafeInteger(value) && value > 0
    const ends = body.ends === undefined ? undefined : isRoomEnds(body.ends) ? body.ends : null
    const expirations = event.tags.filter((t) => t[0] === 'expiration')
    if (ends === null || expirations.length > 1) return null
    if (expirations.length === 1 && (ends === undefined || expirations[0][1] !== String(ends))) return null
    if (body.relays !== undefined && !isInvitationRelays(body.relays)) return null
    const admission = ends === undefined ? { secret, persistent: true, epoch: 0 } : { secret, persistent: true, epoch: 0, endsAt: ends }
    if (body.relays !== undefined) admission.relays = [...body.relays]
    return admission
  } catch {
    return null
  }
}

/** 0.8.0's `decodeInvitationRetirementNotice` body handling, copied line
 *  for line after the same envelope checks. */
function readRetirementAs080(event) {
  const body = JSON.parse(event.content)
  return body.v === 1 ? { ended: body.ended === true } : undefined
}

/** 0.8.0's `decodeRekeyEvent` body handling, copied line for line after the
 *  same envelope checks, for a closure (which seals no secret to anybody). */
function readRekeyAs080(event, current) {
  const epoch = Number(event.tags.find((t) => t[0] === 'epoch')[1])
  const body = JSON.parse(nip44.v2.decrypt(event.content, current.key))
  if (body.v !== 1 || body.epoch !== epoch) return null
  if (!Array.isArray(body.removed) || !body.removed.every((p) => typeof p === 'string' && /^[0-9a-f]{64}$/i.test(p))) return null
  if (typeof body.keys !== 'object' || body.keys === null) return null
  const notice = { epoch, removed: [...new Set(body.removed.map((p) => p.toLowerCase()))].sort(), closed: body.closed === true, at: event.created_at }
  if (body.scheduled === true && notice.removed.length === 0 && !notice.closed) notice.scheduled = true
  return notice
}

// --- Readers, as JSON --------------------------------------------------------

const admissionJson = (a) =>
  a && {
    secretHex: hex(a.secret),
    persistent: a.persistent,
    epoch: a.epoch,
    ...(a.endsAt !== undefined ? { endsAt: a.endsAt } : {}),
    ...(a.relays ? { relays: a.relays } : {}),
    ...(a.destruct ? { destruct: true } : {}),
  }
const readInvitation = (event) => admissionJson(decodePersistentInvitation(event, INVITATION))
const welcomeBody = (event) => nip44.v2.decrypt(event.content, WELCOME_KEY)

const e1 = deriveEpoch(EPOCH_1)
const noticeJson = (n) =>
  n && {
    epoch: n.epoch,
    removed: n.removed,
    closed: n.closed,
    ...(n.destruct ? { destruct: true } : {}),
    ...(n.scheduled ? { scheduled: true } : {}),
    ...(n.secret ? { secretHex: hex(n.secret) } : {}),
    at: n.at,
  }
const readNotice = (event) => noticeJson(decodeRekeyEvent(event, { roomId, authority: INVITER, current: e1, deviceSk: DEVICE_SK }))
const readEvidence = (event) => readRekeyEvidence(event, { roomId, authority: INVITER, previous: e1 })

// --- The group invitation ----------------------------------------------------

const invitationOptions = { invitation: INVITATION, inviterSk: INVITER_SK, roomSecret: ROOM_SECRET, now: NOW, endsAt: ENDS, relays: RELAYS }
const flagged = recorded(['invitation/body', 'invitation/aux'], () => encodePersistentInvitation({ ...invitationOptions, destruct: true }))
// The same invitation with the same draws and no flag: every invitation before 0.9.0.
const unflaggedInvitation = recorded(['invitation/body', 'invitation/aux'], () => encodePersistentInvitation(invitationOptions))

const noEndOptions = { invitation: INVITATION, inviterSk: INVITER_SK, roomSecret: ROOM_SECRET, now: NOW }
const noEnd = recorded(['invitation-no-end/body', 'invitation-no-end/aux'], () => encodePersistentInvitation({ ...noEndOptions, destruct: true }))

const invitationBody = (extra) => ({ v: 3, room: roomId, secret: base64urlnopad.encode(ROOM_SECRET), ...extra })
const MALFORMED_FLAGS = { false: false, string: 'true', number: 1, null: null }
const malformedInvitations = Object.fromEntries(
  Object.entries(MALFORMED_FLAGS).map(([k, destruct]) => [
    k,
    handBuilt(`invitation-malformed-${k}`, { kind: KINDS.GROUP_INVITATION, tags: [['d', INVITATION_ID]], key: WELCOME_KEY, body: invitationBody({ destruct }) }),
  ]),
)

// Two signed copies of one invitation: an older one that self-destructs, a
// newer one written without the flag (an older writer, or a slip).
const older = recorded(['copies/older/body', 'copies/older/aux'], () => encodePersistentInvitation({ ...noEndOptions, destruct: true }))
const newer = recorded(['copies/newer/body', 'copies/newer/aux'], () => encodePersistentInvitation({ ...noEndOptions, now: NOW + 60, relays: RELAYS }))
/** What the real joiner admits with, hearing `events` in that order. */
const admitFrom = (events) =>
  requestPersistentRoomAdmission({
    invitation: INVITATION,
    transport: {
      async publish() {},
      subscribe(_filters, onEvent, onEose) {
        for (const event of events) onEvent(event)
        onEose?.()
        return () => {}
      },
      close() {},
    },
  }).then(admissionJson)
const copiesAdmitted = { olderFirst: await admitFrom([older.event, newer.event]), newerFirst: await admitFrom([newer.event, older.event]) }

// --- The retirement ------------------------------------------------------------

const retirementOptions = { invitation: INVITATION, inviterSk: INVITER_SK, now: NOW + 3_600, ended: true }
const retired = recorded(['retirement/aux'], () => encodeInvitationRetirement({ ...retirementOptions, destruct: true }))
const unflaggedRetirement = recorded(['retirement/aux'], () => encodeInvitationRetirement(retirementOptions))
const retirementNotEnded = handBuilt('retirement-not-ended', {
  kind: KINDS.INVITATION_RETIREMENT,
  tags: [['d', INVITATION_ID]],
  body: { v: 1, destruct: true },
  createdAt: NOW + 3_600,
})

// --- The closing rekey ---------------------------------------------------------

const closureOptions = { roomId, authoritySk: INVITER_SK, current: e1, next: EPOCH_2, recipients: [DEVICE], removed: [], closed: true, now: NOW + 3_600 }
const closure = recorded(['closure/body', 'closure/aux'], () => encodeRekeyEvent({ ...closureOptions, destruct: true }))
const unflaggedClosure = recorded(['closure/body', 'closure/aux'], () => encodeRekeyEvent(closureOptions))

const rekeyTags = [['d', roomId], ['epoch', '2']]
const openWithRemoval = handBuilt('open-removal', { kind: KINDS.ROOM_REKEY, tags: rekeyTags, key: e1.key, body: { v: 1, epoch: 2, removed: [GONE], destruct: true, keys: {} } })
const openScheduled = handBuilt('open-scheduled', { kind: KINDS.ROOM_REKEY, tags: rekeyTags, key: e1.key, body: { v: 1, epoch: 2, removed: [], destruct: true, scheduled: true, keys: {} } })

// --- Vectors -----------------------------------------------------------------

const invitationInput = { invitation: { bearerHex: hex(BEARER), inviter: INVITER, persistent: true }, inviterSkHex: hex(INVITER_SK), roomSecretHex: hex(ROOM_SECRET), roomId }

const vectors = [
  {
    name: 'destruct-invitation',
    kind: 'positive',
    note: 'A kind-1463 group invitation for a conference room that self-destructs: `"destruct": true` inside the encrypted body, after `ends` and before `relays` (body order v, room, secret, ends, destruct, relays), and never as a tag, so a relay cannot tell it from any other invitation. A reader accepts the flag only as `true` (see `destruct-invitation-malformed`) and reports it as `destruct: true` on the admission. `randomHex`: the body nonce, the aux-rand. `unflagged` is the same invitation with the same draws and no flag, which is every invitation before 0.9.0: its body is `bodyJson` without `"destruct":true,`. `oldReader` is what a 0.8.0 reader makes of the flagged event: the same admission without `destruct`, so an old client joins and ends the room the old way.',
    input: { ...invitationInput, createdAt: NOW, endsAt: ENDS, relays: RELAYS, ...flagged, unflagged: unflaggedInvitation },
    output: {
      bodyJson: welcomeBody(flagged.event),
      unflaggedBodyJson: welcomeBody(unflaggedInvitation.event),
      admission: readInvitation(flagged.event),
      unflaggedAdmission: readInvitation(unflaggedInvitation.event),
      oldReader: admissionJson(readInvitationAs080(flagged.event)),
    },
  },
  {
    name: 'destruct-invitation-no-end',
    kind: 'positive',
    note: 'A group invitation with `destruct` and no `ends`: valid. The room has no fixed end and self-destructs when its authority closes it. No expiration tag, as for any group with no end. `randomHex`: the body nonce, the aux-rand.',
    input: { ...invitationInput, createdAt: NOW, ...noEnd },
    output: { bodyJson: welcomeBody(noEnd.event), admission: readInvitation(noEnd.event), oldReader: admissionJson(readInvitationAs080(noEnd.event)) },
  },
  {
    name: 'destruct-invitation-malformed',
    kind: 'negative',
    note: 'Group invitations signed by the inviter whose body carries `destruct` as something other than `true`: `false`, the string `"true"`, `1`, `null`. Built by hand (`bodyJson`, then `randomHex`: the body nonce, the aux-rand). A reader refuses each envelope outright (null), as it refuses a malformed `ends`. A 0.8.0 reader, which never looks at the field, still admits each one (`oldReader`).',
    input: { ...invitationInput, cases: malformedInvitations },
    output: {
      admission: Object.fromEntries(Object.entries(malformedInvitations).map(([k, v]) => [k, readInvitation(v.event)])),
      oldReader: Object.fromEntries(Object.entries(malformedInvitations).map(([k, v]) => [k, admissionJson(readInvitationAs080(v.event))])),
    },
  },
  {
    name: 'destruct-invitation-copies',
    kind: 'positive',
    note: 'Two signed copies of one group invitation that disagree: `older` (created_at NOW) self-destructs, `newer` (NOW + 60) names the room relays and has no flag. `requestPersistentRoomAdmission` hears both and admits with `destruct: true` in either order (`olderFirst`, `newerFirst`; `alone` is each copy read by itself): self-destruct is sticky, as the earlier `ends` is, so a stale or careless copy can never keep a room\'s content alive. The relays still come from the newest copy that names any. `randomHex` on each: the body nonce, the aux-rand.',
    input: { ...invitationInput, older, newer },
    output: { ...copiesAdmitted, alone: { older: readInvitation(older.event), newer: readInvitation(newer.event) } },
  },
  {
    name: 'destruct-retirement',
    kind: 'positive',
    note: 'A kind-1461 retirement of the invitation above, saying the room was ended and self-destructs: content `{"v":1,"ended":true,"destruct":true}`. This content is plain JSON, not encrypted, as `ended` always was; the `d` tag is the invitation id, which nobody without the link can tie to a room. A reader reports `{ ended: true, destruct: true }`. `randomHex`: the aux-rand. `unflagged` is the same retirement with the same draw and no flag (0.8.0\'s `ended` retirement). `oldReader`: a 0.8.0 reader sees an ordinary ended room.',
    input: { invitation: invitationInput.invitation, inviterSkHex: hex(INVITER_SK), createdAt: NOW + 3_600, ...retired, unflagged: unflaggedRetirement },
    output: {
      notice: decodeInvitationRetirementNotice(retired.event, INVITATION),
      unflaggedNotice: decodeInvitationRetirementNotice(unflaggedRetirement.event, INVITATION),
      oldReader: readRetirementAs080(retired.event),
    },
  },
  {
    name: 'destruct-retirement-not-ended',
    kind: 'negative',
    note: 'A retirement signed by the inviter whose content is `{"v":1,"destruct":true}`: a flag without `ended`. The encoder refuses it (`encoder`), so it is built by hand (`randomHex`: the aux-rand). A reader still honours the retirement, since a retired link must stay retired, and does not believe the flag: `{ ended: false }`.',
    input: { invitation: invitationInput.invitation, ...retirementNotEnded },
    output: {
      encoder: refused(() => encodeInvitationRetirement({ ...retirementOptions, ended: false, destruct: true })),
      notice: decodeInvitationRetirementNotice(retirementNotEnded.event, INVITATION),
    },
  },
  {
    name: 'destruct-closure',
    kind: 'positive',
    note: 'A kind-1462 rekey from epoch 1 to 2 that closes the room and self-destructs it: `"closed": true, "destruct": true` inside the body encrypted to epoch 1 (body order v, epoch, removed, closed, destruct, keys), and never as a tag. A closure seals the new secret to nobody, so `keys` is empty and the only draws are `randomHex`: the body nonce, the aux-rand. `unflagged` is the same closure with the same draws and no flag (every closure before 0.9.0). `notice` is `decodeRekeyEvent`, `evidence` is `readRekeyEvidence`; both report `destruct`. `oldReader`: a 0.8.0 reader sees an ordinary close.',
    input: { roomId, authority: INVITER, authoritySkHex: hex(INVITER_SK), previous: { epoch: 1, secretHex: hex(EPOCH_1.secret) }, next: { epoch: 2, secretHex: hex(EPOCH_2.secret) }, recipients: [DEVICE], deviceSkHex: hex(DEVICE_SK), createdAt: NOW + 3_600, ...closure, unflagged: unflaggedClosure },
    output: {
      bodyJson: nip44.v2.decrypt(closure.event.content, e1.key),
      unflaggedBodyJson: nip44.v2.decrypt(unflaggedClosure.event.content, e1.key),
      notice: readNotice(closure.event),
      evidence: readEvidence(closure.event),
      unflaggedNotice: readNotice(unflaggedClosure.event),
      oldReader: readRekeyAs080(closure.event, e1),
    },
  },
  {
    name: 'destruct-rekey-open',
    kind: 'negative',
    note: 'Two rekeys from epoch 1 to 2, signed by the authority, whose bodies carry `destruct` without `closed`: beside a removal (`withRemoval`) and beside the scheduled marker (`withScheduled`). The encoder refuses both (`encoder`), so they are built by hand (`bodyJson`, then `randomHex`: the body nonce, the aux-rand). A reader still reads each rekey, so the removal is announced and the device moves on, and does not believe the flag: it is absent from `notice` and `evidence`.',
    input: { roomId, authority: INVITER, previous: { epoch: 1, secretHex: hex(EPOCH_1.secret) }, deviceSkHex: hex(DEVICE_SK), withRemoval: openWithRemoval, withScheduled: openScheduled },
    output: {
      encoder: {
        withRemoval: refused(() => encodeRekeyEvent({ ...closureOptions, closed: false, removed: [GONE], destruct: true })),
        withScheduled: refused(() => encodeRekeyEvent({ ...closureOptions, closed: false, scheduled: true, destruct: true })),
      },
      withRemoval: { notice: readNotice(openWithRemoval.event), evidence: readEvidence(openWithRemoval.event) },
      withScheduled: { notice: readNotice(openScheduled.event), evidence: readEvidence(openScheduled.event) },
    },
  },
]

// --- Self-checks ------------------------------------------------------------------

const v = (name) => vectors.find((x) => x.name === name).output
const inv = v('destruct-invitation')
if (!inv.admission?.destruct || inv.admission.endsAt !== ENDS || inv.admission.relays?.length !== 1) throw new Error('destruct-invitation does not read as self-destructing')
if (inv.unflaggedAdmission.destruct || inv.unflaggedBodyJson !== inv.bodyJson.replace('"destruct":true,', '')) throw new Error('the unflagged invitation is not the 0.8.0 body')
if (inv.oldReader.destruct || JSON.stringify(inv.oldReader) !== JSON.stringify(inv.unflaggedAdmission)) throw new Error('the old reader does not admit as before')
if (!v('destruct-invitation-no-end').admission?.destruct || 'endsAt' in v('destruct-invitation-no-end').admission) throw new Error('destruct without ends is not valid')
const mal = v('destruct-invitation-malformed')
for (const k of Object.keys(MALFORMED_FLAGS)) if (mal.admission[k] !== null || !mal.oldReader[k]) throw new Error(`malformed ${k} was not refused, or the old reader refused it`)
const cop = v('destruct-invitation-copies')
for (const k of ['olderFirst', 'newerFirst']) if (!cop[k]?.destruct || cop[k].relays?.[0] !== RELAYS[0]) throw new Error(`copies heard ${k} did not stick`)
if (cop.alone.newer.destruct || !cop.alone.older.destruct) throw new Error('the copies are not the disagreement they should be')
const ret = v('destruct-retirement')
if (JSON.stringify(ret.notice) !== JSON.stringify({ ended: true, destruct: true }) || JSON.stringify(ret.unflaggedNotice) !== JSON.stringify({ ended: true }) || JSON.stringify(ret.oldReader) !== JSON.stringify({ ended: true })) throw new Error('destruct-retirement reads wrongly')
if (v('destruct-retirement-not-ended').encoder !== 'refused' || JSON.stringify(v('destruct-retirement-not-ended').notice) !== JSON.stringify({ ended: false })) throw new Error('a plain retirement self-destructed')
const clo = v('destruct-closure')
if (!clo.notice?.destruct || !clo.notice.closed || !clo.evidence?.destruct || clo.unflaggedNotice.destruct) throw new Error('destruct-closure does not read as self-destructing')
if (clo.unflaggedBodyJson !== clo.bodyJson.replace('"destruct":true,', '')) throw new Error('the unflagged closure is not the 0.8.0 body')
if (!clo.oldReader?.closed || 'destruct' in clo.oldReader) throw new Error('the old reader does not see a close')
const open = v('destruct-rekey-open')
if (open.encoder.withRemoval !== 'refused' || open.encoder.withScheduled !== 'refused') throw new Error('the encoder self-destructed an open room')
for (const k of ['withRemoval', 'withScheduled']) if (!open[k].notice || open[k].notice.destruct || !open[k].evidence || open[k].evidence.destruct) throw new Error(`${k} read as self-destructing`)
if (open.withRemoval.notice.removed[0] !== GONE || !open.withScheduled.notice.scheduled) throw new Error('an open rekey with the flag was not read as before')

const doc = {
  protocolVersion: 'kithmoot/v1',
  generatedBy: 'scripts/generate-destruct.mjs (forgesworn/fold-kit)',
  nostrToolsVersion,
  groups: { destruct: vectors },
}

writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n')
console.log(`generate-destruct: wrote ${outPath} (${vectors.length} vectors)`)
