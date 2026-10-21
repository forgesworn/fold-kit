#!/usr/bin/env node
// Known-answer vectors for a room's group storage nodes: the optional
// `storage` list in the group invitation body (`encodePersistentInvitation`),
// last in the body after `relays`, holding 0 to 8 canonical node base URLs.
// The rule is the grammar in `src/invitation-storage.ts`; see EXTRACTION.md
// "Room storage nodes".
//
// Written in KithMoot's vector format (`protocolVersion`, `groups`, and per
// vector `name`/`kind`/`note`/`input`/`expected`), so the file can be copied
// verbatim into KithMoot's `vectors/` and from there into KithMoot Android's.
// Every input is a fixed labelled value from `vectors/lib/determinism.mjs`,
// and every random draw a real encoder makes is recorded beside the event it
// went into, in draw order. The events no correct encoder writes (a malformed
// list) are built by hand from a recorded body, nonce and aux-rand.
//
// Each positive vector also records what a 0.13.0 reader makes of the new
// event (`oldReader`): that reader's body handling, copied line for line
// below, so a port can check it is no worse off on an old release. The
// `storage-absent` vector pins two events recorded from 0.13.0's own encoder:
// today's encoder must rebuild them byte for byte.
//
// Run after `npm run build`: `npm run generate-storage`. Verified against
// `src/` directly by `vectors/verify-storage.test.ts`.
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
  deriveInvitationId,
  roomInvitation,
  isInvitationRelays,
  isStorageNodeBase,
  storageNodeFromBase,
  MAX_STORAGE_NODE_URL_LENGTH,
  encodePersistentInvitation,
  decodePersistentInvitation,
  requestPersistentRoomAdmission,
} from '../dist/index.js'
import { requestPersistentRoomAdmissionEvidence } from '../dist/persistent-invitation-evidence.js'

const here = dirname(fileURLToPath(import.meta.url))
const outPath = join(here, '..', 'vectors', 'storage-vectors.json')
const nostrToolsVersion = JSON.parse(readFileSync(join(here, '..', 'node_modules', 'nostr-tools', 'package.json'), 'utf8')).version

// --- Fixed inputs ------------------------------------------------------------

const NOW = 1_800_000_000
const ENDS = NOW + 86_400
const RELAYS = ['wss://relay.example.com/']
const INVITER_SK = deriveSecretKey('storage/inviter')
const INVITER = getPublicKey(INVITER_SK)
const BEARER = seed32('storage/bearer')
const INVITATION = roomInvitation(BEARER, INVITER, true)
const INVITATION_ID = deriveInvitationId(INVITATION)
const ROOM_SECRET = seed32('storage/room-secret')
const { roomId } = deriveRoom(ROOM_SECRET)
const WELCOME_KEY = hkdf(sha256, BEARER, undefined, 'kithmoot/v3/group-invitation-key', 32)

/** A made-up onion v3 host: 56 characters of a-z and 2-7. */
const ONION = 'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion'
const NODE_A = 'https://grove.example.net'
const NODES_B = ['https://example.org:8443/wb', 'https://grove.example.net']
const NODES_C = ['https://grove.example.net', 'https://example.org:8443/wb', 'http://127.0.0.1:8080']

const r = (label) => seed32(`storage/random/${label}`)
const hex = bytesToHex

function plain(event) {
  const { id, pubkey, created_at, kind, tags, content, sig } = event
  return { id, pubkey, created_at, kind, tags, content, sig }
}

function recorded(label, fn) {
  const labels = [`${label}/body`, `${label}/aux`]
  const draws = labels.map(r)
  const event = withStubbedRandomness(draws, fn)
  return { event: plain(event), randomHex: draws.map(hex) }
}

/** An event signed by the inviter (the room's authority) around a body it
 *  was handed: what a broken or hostile encoder could publish. `randomHex`:
 *  the NIP-44 nonce, then the aux-rand. */
function handBuilt(label, body, createdAt = NOW) {
  const bodyJson = JSON.stringify(body)
  const nonce = r(`${label}/body`)
  const aux = r(`${label}/aux`)
  const content = withStubbedRandomness([nonce], () => nip44.v2.encrypt(bodyJson, WELCOME_KEY))
  const event = finalizeDeterministic({ kind: KINDS.GROUP_INVITATION, created_at: createdAt, tags: [['d', INVITATION_ID]], content }, INVITER_SK, aux)
  return { event: plain(event), randomHex: [hex(nonce), hex(aux)], bodyJson }
}

const invitationBody = (extra) => ({ v: 3, room: roomId, secret: base64urlnopad.encode(ROOM_SECRET), ...extra })
const welcomeBody = (event) => nip44.v2.decrypt(event.content, WELCOME_KEY)

/** The message the encoder throws for `storage`, or 'encoded'. */
function encoderMessage(storage) {
  try {
    encodePersistentInvitation({ invitation: INVITATION, inviterSk: INVITER_SK, roomSecret: ROOM_SECRET, now: NOW, storage })
    return 'encoded'
  } catch (error) {
    return error.message
  }
}

// --- The 0.13.0 reader, copied line for line ---------------------------------

/**
 * The group invitation as 0.13.0's `decodePersistentInvitation` reads it,
 * once the envelope checks (kind, signer, signature, `d` tag; unchanged) have
 * passed: its body handling, copied line for line. It builds its answer from
 * named fields, so `storage` is never seen.
 */
function readInvitationAs0130(event) {
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
    if (body.destruct !== undefined && body.destruct !== true) return null
    const admission = ends === undefined ? { secret, persistent: true, epoch: 0 } : { secret, persistent: true, epoch: 0, endsAt: ends }
    if (body.relays !== undefined) admission.relays = [...body.relays]
    if (body.destruct === true) admission.destruct = true
    return admission
  } catch {
    return null
  }
}

/**
 * What 0.13.0's strict evidence path makes of a set of copies, as far as
 * `storage` goes: its body allowlist is `v, room, secret, ends, destruct,
 * relays`, so a copy that carries `storage` fails `dataRecord`, is skipped
 * (`if (!decoded) return`) and is never retained, and the copies left are
 * resolved as before. Checked once against a build of 0.13.0 (commit 020d85e)
 * for the case in `storage-strict-old-reader`.
 */
function oldStrictOutcome(events) {
  const kept = events.filter((e) => {
    const keys = Object.keys(JSON.parse(welcomeBody(e)))
    return keys.every((k) => ['v', 'room', 'secret', 'ends', 'destruct', 'relays'].includes(k))
  })
  if (!kept.length) return { status: 'held', reason: 'unavailable', retirementEventIds: [] }
  const admission = readInvitationAs0130(kept[0])
  return {
    status: 'admitted',
    admission: admissionJson(admission),
    contributors: { room: kept.map((e) => e.id).sort(), ends: [], destruct: [], relays: [] },
  }
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
    ...(a.storage ? { storage: a.storage } : {}),
    ...(a.storageAt !== undefined ? { storageAt: a.storageAt } : {}),
  }
const readInvitation = (event) => admissionJson(decodePersistentInvitation(event, INVITATION))

/** A transport that replays `events` and signals the end of the stored events. */
const replay = (events) => ({
  async publish() {},
  subscribe(_filters, onEvent, onEose) {
    for (const event of events) onEvent(event)
    onEose?.()
    return () => {}
  },
  close() {},
})
/** What the real lenient joiner admits with, hearing `events` in that order. */
const lenient = (events) => requestPersistentRoomAdmission({ invitation: INVITATION, transport: replay(events) }).then(admissionJson)
/** What the real strict evidence query makes of `events`, in that order. */
const strict = async (events) => {
  const { outcome } = await requestPersistentRoomAdmissionEvidence({ invitation: INVITATION, transport: replay(events) })
  if (outcome.status === 'held') return { status: 'held', reason: outcome.reason, retirementEventIds: [...outcome.retirementEventIds] }
  return {
    status: 'admitted',
    admission: admissionJson(outcome.admission),
    contributors: Object.fromEntries(Object.entries(outcome.contributors).map(([k, v]) => [k, [...v]])),
  }
}

// --- The 0.13.0 events: recorded from 0.13.0's own encoder ----------------------
//
// Built with commit 020d85e's `encodePersistentInvitation` under the fixed
// keys above and these random draws (`storage/random/golden/...`). They are
// literals, not output of this tree, so `storage-absent` compares today's
// encoder with what 0.13.0 actually wrote.

const GOLDEN_0130 = {
  plain: {
    event: {
      id: 'ca2271cae9b3e6657b6de88b5d444f2d556377207be1775541f5cc288ce9cb93',
      pubkey: 'caddad97f8824376a936b17ac2c0f5bbe2c6038e1b581f21c7015517466f118a',
      created_at: 1800000000,
      kind: 1463,
      tags: [['d', '53d54d568559f777c1ec1e7e2c9fa805277b4fb51cd217b97560eac815605025']],
      content: 'AoYUImhbnzJrNvMLQ+KrLoPZeddgwqF+zkdgIAcZ4hP4z79xrlnUNdV31FZGDbMmbHM+pPHaNPXFciplA0au/qrjURkmdAD6Acaplu9RlmPA8GeChMaOZuaNR5W7ShLJCQUE32kqfDTIUW5UuVptFBEDCbi5KzCBHfAfvqxrlvgYlBufAtl5l1VsA6AFUHC2xM7r75cBJqMN5DEEgvPUIeKQhlaqKvjjgC5ce2t6eR6Poi7/4VVTbRSWZ3nwUC0h78Wy65OZMsT5jOd9dWgMnj+ml0FmWB3NIqOuSMvkjpRTqVM=',
      sig: '3542c9cffa6ab6189626b83242bda3e77e2b9b56220d1027fc5abcb501f5568af51d357d35a638b4175aed6ddbb0f8030cff0975fac392a869119fdb21538a08',
    },
    draws: ['golden/plain/body', 'golden/plain/aux'],
  },
  full: {
    event: {
      id: '5042b581b34988f7fa435010ddd33ddf437f718da678019501a81867f2677e90',
      pubkey: 'caddad97f8824376a936b17ac2c0f5bbe2c6038e1b581f21c7015517466f118a',
      created_at: 1800000000,
      kind: 1463,
      tags: [
        ['d', '53d54d568559f777c1ec1e7e2c9fa805277b4fb51cd217b97560eac815605025'],
        ['expiration', '1800086400'],
      ],
      content: 'AlJxN3FbI308f1PKRlWvrTCh/86YDVMC2tntTH6m3ZWJzWz6qjlH8Q1tCaUkgWWg+Y5U3N6BbaReK8o5X59hQdbhlxS2VQwzWyDPhBWIjM6GUc7o0ohRq5xDJx0YCyytDwQlWYbuk5me5zeiklTzaLEIFd6MNSyN++kuz2a58m978yI8ZqFUFxataoDAS2A8NBdr/IQxfpvq2FtvfZJO8JjI1cZnI2QIjV2EhaQ1VxX4pOWcU86a9anXRBT333/zpGAUgq2DoyyYiMJXWkAH+v3qsReLMYfa+/14ePHPKvwWBZmHfpMtDfpWHZy0yQis+unLJNhbpmAO8I15kMGp+jH26Y/YlADQk+xMLQ8cfHIyS0FszXH2ziSAKy9CAjC5Jkm5',
      sig: '37266a53d6f4c12bd42f9d466e0c524d31e79cbb97c1db39fa34771ae3fd4d0b24b1cab51b7b8cd6465a4929ba227203593788711f3fd5ffed8838ba3c411d54',
    },
    draws: ['golden/full/body', 'golden/full/aux'],
  },
}
const golden = (g) => ({ event: g.event, randomHex: g.draws.map((l) => hex(r(l))) })

// --- The group invitation ----------------------------------------------------

const invitationInput = { invitation: { bearerHex: hex(BEARER), inviter: INVITER, persistent: true }, inviterSkHex: hex(INVITER_SK), roomSecretHex: hex(ROOM_SECRET), roomId }
const baseOptions = { invitation: INVITATION, inviterSk: INVITER_SK, roomSecret: ROOM_SECRET, now: NOW }

const single = recorded('invitation', () => encodePersistentInvitation({ ...baseOptions, storage: [NODE_A] }))
const fullOrder = recorded('full-order', () => encodePersistentInvitation({ ...baseOptions, endsAt: ENDS, destruct: true, relays: RELAYS, storage: NODES_C }))
const withdrawn = recorded('withdrawn', () => encodePersistentInvitation({ ...baseOptions, storage: [] }))
/** Today's encoder, fed 0.13.0's recorded draws, with no `storage`. */
const rebuilt = (g, extra) => plain(withStubbedRandomness(g.draws.map(r), () => encodePersistentInvitation({ ...baseOptions, ...extra })))

// --- Entries -------------------------------------------------------------------

const ACCEPTS = [
  'https://grove.example.net',
  'https://grove.example.net:8443',
  'https://example.net/wb/node-1',
  'http://localhost:3000',
  'http://127.0.0.1:8080',
  `http://${ONION}`,
  'https://192.0.2.10',
  'https://localhost',
  'https://example.net:65535',
  'http://127.255.255.254',
  'https://example.net/a.b/c_d/e~f/...',
]
const acceptCases = ACCEPTS.map((entry, i) => {
  const node = storageNodeFromBase(entry)
  return { entry, server: node.server, isStorageNodeBase: isStorageNodeBase(entry), ...handBuilt(`accept-${i}`, invitationBody({ storage: [entry] })) }
})

const REFUSALS = [
  ['trailing slash', 'https://example.net/wb/'],
  ['root slash', 'https://grove.example.net/'],
  ['upper-case host', 'https://Grove.Example.net'],
  ['upper-case scheme', 'HTTPS://grove.example.net'],
  ['default port 443', 'https://grove.example.net:443'],
  ['port 80 on http', 'http://localhost:80'],
  ['port with a leading zero', 'https://grove.example.net:08080'],
  ['port 0', 'https://grove.example.net:0'],
  ['port 65536', 'https://grove.example.net:65536'],
  ['an empty port', 'https://grove.example.net:'],
  ['a query', 'https://grove.example.net?x=1'],
  ['a fragment', 'https://grove.example.net#x'],
  ['user info', 'https://user:pw@grove.example.net'],
  ['http on a public host', 'http://grove.example.net'],
  ['http on a subdomain of localhost', 'http://a.localhost'],
  ['a ws scheme', 'ws://grove.example.net'],
  ['an IPv6 literal', 'https://[::1]'],
  ['a trailing dot', 'https://grove.example.net.'],
  ['a short IPv4 form', 'http://127.1'],
  ['a hex IPv4 form', 'http://0x7f.0.0.1'],
  ['an octet with a leading zero', 'http://127.000.0.1'],
  ['an octet over 255', 'https://192.0.2.256'],
  ['a numeric last label with three octets', 'https://example.net.1'],
  ['a percent-encoded path', 'https://example.net/a%2Fb'],
  ['a dot segment', 'https://example.net/a/./b'],
  ['a dot-dot segment', 'https://example.net/a/../b'],
  ['an empty segment', 'https://example.net//x'],
  ['a space in the path', 'https://example.net/a b'],
  ['a non-ASCII host', 'https://exämple.net'],
  ['a Kelvin sign in the host', 'https://Kexample.net'],
  ['a label starting with a hyphen', 'https://-grove.example.net'],
  ['a label ending with a hyphen', 'https://grove-.example.net'],
  ['an underscore in the host', 'https://gro_ve.example.net'],
  ['a 64 character label', `https://${'a'.repeat(64)}.example.net`],
  ['257 characters', `https://example.net/${'a'.repeat(MAX_STORAGE_NODE_URL_LENGTH + 1 - 'https://example.net/'.length)}`],
  ['an empty string', ''],
  ['no scheme', 'example.net'],
]
const refusalCases = REFUSALS.map(([label, entry], i) => ({
  label,
  entry,
  ...handBuilt(`entry-refusal-${i}`, invitationBody({ storage: [entry] })),
}))

const LIST_REFUSALS = [
  ['not an array', 'https://grove.example.net'],
  ['null', null],
  ['a number', 7],
  ['an object', { 0: 'https://grove.example.net' }],
  ['a number in the list', ['https://grove.example.net', 7]],
  ['an object entry', [{ base: 'https://grove.example.net' }]],
  ['nine entries', Array.from({ length: 9 }, (_, i) => `https://node${i}.example.net`)],
  ['two ports on one host', ['https://example.net', 'https://example.net:8443']],
  ['the same entry twice', ['https://example.net', 'https://example.net']],
]
const listCases = LIST_REFUSALS.map(([label, storage], i) => ({ label, storage, ...handBuilt(`list-refusal-${i}`, invitationBody({ storage })) }))

const eight = Array.from({ length: 8 }, (_, i) => `https://node${i}.example.net`)
const eightEvent = recorded('eight', () => encodePersistentInvitation({ ...baseOptions, storage: eight }))

// --- Copies ----------------------------------------------------------------------

const copy = (name, createdAt, extra) => ({ name, createdAt, ...extra, ...recorded(`copies/${name}`, () => encodePersistentInvitation({ ...baseOptions, now: createdAt, ...extra })) })
const permutations = (items) => (items.length <= 1 ? [items] : items.flatMap((x, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [x, ...rest])))
const byName = (copies) => Object.fromEntries(copies.map((c) => [c.name, c.event]))
async function orders(copies, names) {
  const events = byName(copies)
  const out = {}
  for (const order of permutations(names)) {
    const list = order.map((n) => events[n])
    out[order.join(',')] = { lenient: await lenient(list), strict: await strict(list) }
  }
  return out
}
const copyInput = (copies) => copies.map(({ name, createdAt, storage, relays, event, randomHex }) => ({ name, createdAt, ...(storage ? { storage } : {}), ...(relays ? { relays } : {}), event, randomHex }))

const older = copy('older', NOW, { storage: [NODE_A] })
const newer = copy('newer', NOW + 10, { storage: NODES_B })
const silent = copy('silent', NOW + 20, {})
const empty = copy('empty', NOW + 30, { storage: [] })
const olderEmpty = copy('older-empty', NOW - 30, { storage: [] })
const tieA = copy('tie-a', NOW + 50, { storage: [NODE_A] })
const tieB = copy('tie-b', NOW + 50, { storage: NODES_B })
const mergeCopies = [older, newer, silent, empty, olderEmpty, tieA, tieB]

const indA = copy('ind-a', NOW, { relays: ['wss://old.example.com/'], storage: [NODE_A] })
const indB = copy('ind-b', NOW + 10, { relays: ['wss://new.example.com/'] })
const indC = copy('ind-c', NOW + 5, { storage: NODES_B })
const independentCopies = [indA, indB, indC]

const strictPlain = copy('plain', NOW, {})
const strictStorage = copy('with-storage', NOW + 1, { storage: NODES_B })

// --- Vectors -----------------------------------------------------------------

const vectors = [
  {
    name: 'storage-invitation',
    kind: 'positive',
    note: 'A kind-1463 group invitation that lists one group storage node: `"storage": ["https://grove.example.net"]` inside the encrypted body, after `secret` (body order v, room, secret, storage), and never as a tag. A reader returns `storage` and `storageAt`, the `created_at` of the copy whose list stood. `randomHex`: the body nonce, the aux-rand. `oldReader` is what a 0.13.0 reader makes of this event: the same admission without `storage`, so an old client joins as before (today\'s Android does too).',
    input: { ...invitationInput, createdAt: NOW, storage: [NODE_A], ...single },
    expected: { bodyJson: welcomeBody(single.event), admission: readInvitation(single.event), oldReader: admissionJson(readInvitationAs0130(single.event)) },
  },
  {
    name: 'storage-full-order',
    kind: 'positive',
    note: 'Every optional body key at once, with three nodes: body order v, room, secret, ends, destruct, relays, storage. The nodes keep the order the authority wrote them, which is the order of preference. The `expiration` tag follows `ends` as before. `randomHex`: the body nonce, the aux-rand.',
    input: { ...invitationInput, createdAt: NOW, endsAt: ENDS, destruct: true, relays: RELAYS, storage: NODES_C, ...fullOrder },
    expected: { bodyJson: welcomeBody(fullOrder.event), admission: readInvitation(fullOrder.event), oldReader: admissionJson(readInvitationAs0130(fullOrder.event)) },
  },
  {
    name: 'storage-withdrawn',
    kind: 'positive',
    note: 'An empty list, `"storage": []`: the room\'s authority withdrew every node. It is valid, it is a list, and it stands against an older copy that named nodes (see `storage-merge`). The admission carries `storage: []` and `storageAt`. `randomHex`: the body nonce, the aux-rand.',
    input: { ...invitationInput, createdAt: NOW, storage: [], ...withdrawn },
    expected: { bodyJson: welcomeBody(withdrawn.event), admission: readInvitation(withdrawn.event), oldReader: admissionJson(readInvitationAs0130(withdrawn.event)) },
  },
  {
    name: 'storage-absent',
    kind: 'positive',
    note: 'No `storage` key: the event is byte for byte what 0.13.0 wrote. `recorded0130` holds two events recorded from 0.13.0\'s own encoder (`plain`, and `full` with `ends`, `destruct` and `relays`) under the fixed keys above, with the random draws in `randomHex`; today\'s encoder must rebuild both exactly. The generator checks that the encoder in this tree, given the same draws, writes the same two events. The admission has no `storage` and no `storageAt`, so a body without the key says nothing about nodes. `randomHex`: the body nonce, the aux-rand.',
    input: {
      ...invitationInput,
      createdAt: NOW,
      endsAt: ENDS,
      destruct: true,
      relays: RELAYS,
      recorded0130: { plain: golden(GOLDEN_0130.plain), full: golden(GOLDEN_0130.full) },
    },
    expected: {
      plainBodyJson: welcomeBody(GOLDEN_0130.plain.event),
      fullBodyJson: welcomeBody(GOLDEN_0130.full.event),
      plainAdmission: readInvitation(GOLDEN_0130.plain.event),
      fullAdmission: readInvitation(GOLDEN_0130.full.event),
    },
  },
  {
    name: 'storage-accepts',
    kind: 'positive',
    note: 'Entries the grammar accepts, each with the `server` it implies (its host, exactly as written), alone in a hand-built envelope (`bodyJson`, then `randomHex`: the body nonce, the aux-rand). Each is canonical as it stands: `base` equals `entry`. A reader admits every one of them with `storage` set to the one entry.',
    input: { ...invitationInput, cases: acceptCases },
    expected: { admission: Object.fromEntries(acceptCases.map((c) => [c.entry, readInvitation(c.event)])) },
  },
  {
    name: 'storage-entry-refusals',
    kind: 'negative',
    note: 'One entry per case, each not canonical, alone in a hand-built envelope signed by the inviter (`bodyJson`, then `randomHex`: the body nonce, the aux-rand). A reader refuses each whole envelope (null); the encoder throws the message in `encoder`. A 0.13.0 reader, which never looks at the key, still admits each one (`oldReader`). The grammar, not what a URL parser prints, decides: `127.1`, `0x7f.0.0.1` and `127.000.0.1` are refused even though a parser would read them as 127.0.0.1.',
    input: { ...invitationInput, cases: refusalCases },
    expected: {
      admission: Object.fromEntries(refusalCases.map((c) => [c.label, readInvitation(c.event)])),
      encoder: Object.fromEntries(refusalCases.map((c) => [c.label, encoderMessage([c.entry])])),
      oldReader: Object.fromEntries(refusalCases.map((c) => [c.label, admissionJson(readInvitationAs0130(c.event))])),
    },
  },
  {
    name: 'storage-list-refusals',
    kind: 'negative',
    note: 'Lists the invitation may not carry, each in a hand-built envelope (`bodyJson`, then `randomHex`: the body nonce, the aux-rand): not an array, `null`, a number, an object, a number in the list, an object entry, nine entries, two entries on one host (two ports are two entries on one host, and grants are per host), and the same entry twice. A reader refuses each whole envelope; the encoder throws the message in `encoder`. A 0.13.0 reader still admits each (`oldReader`). Exactly eight entries are valid: see `eight`.',
    input: { ...invitationInput, cases: listCases, eight: { storage: eight, ...eightEvent } },
    expected: {
      admission: Object.fromEntries(listCases.map((c) => [c.label, readInvitation(c.event)])),
      encoder: Object.fromEntries(listCases.map((c) => [c.label, encoderMessage(c.storage)])),
      oldReader: Object.fromEntries(listCases.map((c) => [c.label, admissionJson(readInvitationAs0130(c.event))])),
      eight: readInvitation(eightEvent.event),
    },
  },
  {
    name: 'storage-merge',
    kind: 'positive',
    note: 'Signed copies of one invitation, heard in every order. `older` (NOW) lists A, `newer` (NOW + 10) lists B, `silent` (NOW + 20) has no `storage` key, `empty` (NOW + 30) lists `[]`, `older-empty` (NOW - 30) lists `[]` before any of them, and `tie-a` and `tie-b` (both NOW + 50) disagree in one second. The newest copy that names storage stands, `[]` included, and a copy without the key says nothing, so `older, newer, silent` always gives B whichever is heard first. `lenient` is `requestPersistentRoomAdmission`: between copies of one second the first heard stands. `strict` is `requestPersistentRoomAdmissionEvidence`: the disagreement holds with reason `conflicting-storage`, and `contributors.storage` names the copy that stood. `orders` keys are the copies in the order heard. `randomHex` on each copy: the body nonce, the aux-rand.',
    input: { ...invitationInput, copies: copyInput(mergeCopies) },
    expected: {
      newest: await orders(mergeCopies, ['older', 'newer', 'silent']),
      withdrawn: await orders(mergeCopies, ['newer', 'silent', 'empty']),
      olderEmptyLoses: await orders(mergeCopies, ['older-empty', 'newer']),
      tie: await orders(mergeCopies, ['tie-a', 'tie-b']),
      alone: Object.fromEntries(mergeCopies.map((c) => [c.name, readInvitation(c.event)])),
    },
  },
  {
    name: 'storage-relays-independent',
    kind: 'positive',
    note: 'The relays and the nodes merge independently: the newest copy naming relays (`ind-b`, NOW + 10) is not the newest copy naming nodes (`ind-c`, NOW + 5), and each list comes from its own copy. `contributors.relays` names `ind-b` and `contributors.storage` names `ind-c`. `randomHex` on each copy: the body nonce, the aux-rand.',
    input: { ...invitationInput, copies: copyInput(independentCopies) },
    expected: { orders: await orders(independentCopies, ['ind-a', 'ind-b', 'ind-c']) },
  },
  {
    name: 'storage-strict-old-reader',
    kind: 'positive',
    note: 'Why a keeper that creates a room publishes a plain copy first: a 0.13.0 strict evidence reader refuses a body key it does not know and never retains that copy. Given a plain copy (NOW) and a copy with storage (NOW + 1), `oldStrictReader` is what 0.13.0 makes of them: `admitted`, with no storage, and `contributors` naming only the plain copy. `expected.strict` is the 0.14.0 outcome: the nodes from the later copy, `storageAt` NOW + 1. Heard with only the copy with storage, 0.13.0 strict holds with reason `unavailable` (`oldStrictReaderAlone`), so the plain copy is the only thing it can admit from. The lenient readers of both versions admit either way. `randomHex` on each copy: the body nonce, the aux-rand.',
    input: { ...invitationInput, copies: copyInput([strictPlain, strictStorage]) },
    expected: {
      oldStrictReader: oldStrictOutcome([strictPlain.event, strictStorage.event]),
      oldStrictReaderAlone: oldStrictOutcome([strictStorage.event]),
      strict: await strict([strictPlain.event, strictStorage.event]),
      strictReversed: await strict([strictStorage.event, strictPlain.event]),
      lenient: await lenient([strictPlain.event, strictStorage.event]),
    },
  },
]

// --- Self-checks ------------------------------------------------------------------

const v = (name) => vectors.find((x) => x.name === name).expected
const inv = v('storage-invitation')
if (JSON.stringify(inv.admission.storage) !== JSON.stringify([NODE_A]) || inv.admission.storageAt !== NOW) throw new Error('storage-invitation does not read back')
if ('storage' in inv.oldReader || inv.oldReader.secretHex !== inv.admission.secretHex) throw new Error('the old reader does not admit as before')
if (Object.keys(JSON.parse(inv.bodyJson)).join() !== 'v,room,secret,storage') throw new Error('storage-invitation body order')
if (Object.keys(JSON.parse(v('storage-full-order').bodyJson)).join() !== 'v,room,secret,ends,destruct,relays,storage') throw new Error('storage-full-order body order')
if (JSON.stringify(v('storage-withdrawn').admission.storage) !== '[]') throw new Error('storage-withdrawn does not read as withdrawn')
if (JSON.stringify(rebuilt(GOLDEN_0130.plain, {})) !== JSON.stringify(GOLDEN_0130.plain.event)) throw new Error("today's encoder does not rebuild the 0.13.0 plain event")
if (JSON.stringify(rebuilt(GOLDEN_0130.full, { endsAt: ENDS, destruct: true, relays: RELAYS })) !== JSON.stringify(GOLDEN_0130.full.event)) throw new Error("today's encoder does not rebuild the 0.13.0 full event")
const abs = v('storage-absent')
if ('storage' in abs.plainAdmission || 'storageAt' in abs.fullAdmission) throw new Error('an absent list read as present')
for (const c of acceptCases) if (!c.isStorageNodeBase || storageNodeFromBase(c.entry).base !== c.entry || !readInvitation(c.event)?.storage) throw new Error(`accepts ${c.entry} was refused`)
for (const c of refusalCases) if (isStorageNodeBase(c.entry) || readInvitation(c.event) !== null || !readInvitationAs0130(c.event)) throw new Error(`refusal ${c.label} was not refused, or the old reader refused it`)
for (const c of listCases) if (readInvitation(c.event) !== null || v('storage-list-refusals').encoder[c.label] === 'encoded' && Array.isArray(c.storage)) throw new Error(`list refusal ${c.label} was not refused`)
if (readInvitation(eightEvent.event)?.storage?.length !== 8) throw new Error('eight nodes were refused')
const m = v('storage-merge')
for (const [order, out] of Object.entries(m.newest)) if (JSON.stringify(out.lenient.storage) !== JSON.stringify(NODES_B) || out.lenient.storageAt !== NOW + 10 || out.strict.status !== 'admitted') throw new Error(`merge newest ${order}`)
for (const [order, out] of Object.entries(m.withdrawn)) if (JSON.stringify(out.lenient.storage) !== '[]' || out.lenient.storageAt !== NOW + 30) throw new Error(`merge withdrawn ${order}`)
for (const [order, out] of Object.entries(m.olderEmptyLoses)) if (JSON.stringify(out.lenient.storage) !== JSON.stringify(NODES_B)) throw new Error(`merge older empty ${order}`)
if (m.tie['tie-a,tie-b'].lenient.storage[0] !== NODE_A || m.tie['tie-b,tie-a'].lenient.storage[0] !== NODES_B[0]) throw new Error('the tie is not first heard')
for (const out of Object.values(m.tie)) if (out.strict.status !== 'held' || out.strict.reason !== 'conflicting-storage') throw new Error('the tie did not hold')
for (const out of Object.values(v('storage-relays-independent').orders)) {
  if (out.strict.contributors.relays[0] !== indB.event.id || out.strict.contributors.storage[0] !== indC.event.id) throw new Error('relays and storage did not merge apart')
  if (out.lenient.relays[0] !== 'wss://new.example.com/' || JSON.stringify(out.lenient.storage) !== JSON.stringify(NODES_B)) throw new Error('relays and storage did not merge apart (lenient)')
}
const so = v('storage-strict-old-reader')
if (so.oldStrictReader.admission.storage || so.oldStrictReader.contributors.room.length !== 1 || so.oldStrictReader.contributors.room[0] !== strictPlain.event.id) throw new Error('the 0.13.0 strict outcome is not as modelled')
if (JSON.stringify(so.strict.admission.storage) !== JSON.stringify(NODES_B) || so.strict.admission.storageAt !== NOW + 1) throw new Error('the strict reader did not take the nodes')
if (so.oldStrictReaderAlone.reason !== 'unavailable') throw new Error('0.13.0 strict should hold on a lone storage copy')

const doc = {
  protocolVersion: 'kithmoot/v1',
  generatedBy: 'scripts/generate-storage.mjs (forgesworn/fold-kit)',
  nostrToolsVersion,
  groups: { storage: vectors },
}

writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n')
console.log(`generate-storage: wrote vectors/storage-vectors.json (${vectors.length} vectors)`)
