#!/usr/bin/env node
// Proves every moved module's body is byte-identical to the pinned KithMoot
// source commit this kit was extracted from (see EXTRACTION.md): a script
// that diffs every moved file against the pinned commit, with import lines
// stripped, for zero difference.
//
// Needs a local checkout of the pinned source commit (see EXTRACTION.md for
// the exact commit). Point FOLD_KIT_SOURCE_DIR at that checkout's root:
//
//   FOLD_KIT_SOURCE_DIR=/path/to/kithmoot npm run diff-source
//
// This script only reads from that checkout - it never writes to it.
// KithMoot is public (github.com/forgesworn/kithmoot), so CI checks out the
// pinned commit itself and sets FOLD_KIT_SOURCE_DIR before this runs (see
// .github/workflows/ci.yml). With no FOLD_KIT_SOURCE_DIR set at all - the
// default for a local run that has not fetched that checkout - it prints a
// notice and exits 0 rather than failing, so this remains safe to leave in
// `npm run check` for anyone working in this repo without a KithMoot
// checkout to hand.
import { execFileSync } from 'node:child_process'
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const sourceDir = process.env.FOLD_KIT_SOURCE_DIR
const sourceCommit = process.env.FOLD_KIT_SOURCE_COMMIT ?? '5babfec'

if (!sourceDir) {
  console.log('diff-source: FOLD_KIT_SOURCE_DIR is not set - skipping (see scripts/diff-source.mjs header).')
  process.exit(0)
}
if (!existsSync(sourceDir)) {
  console.error(`diff-source: FOLD_KIT_SOURCE_DIR (${sourceDir}) does not exist`)
  process.exit(1)
}

/** Reads a file at `sourceCommit` from the source checkout, read-only. */
function readAtCommit(relPath) {
  return execFileSync('git', ['show', `${sourceCommit}:${relPath}`], { cwd: sourceDir, encoding: 'utf8' })
}

function readKit(relPath) {
  return readFileSync(join(root, relPath), 'utf8')
}

let failures = 0

/**
 * Whole-file comparison for modules copied with only their import paths
 * changed. `importRewrites` undoes each kit-side import rewrite before
 * diffing, so the comparison is against the pinned source verbatim.
 */
function checkWholeFile(kitPath, sourcePath, importRewrites = []) {
  const kitText = readKit(kitPath)
  const sourceText = readAtCommit(sourcePath)
  let normalised = kitText
  for (const [from, to] of importRewrites) normalised = normalised.split(from).join(to)
  if (normalised !== sourceText) {
    failures += 1
    console.error(`FAIL (whole file): ${kitPath} differs from ${sourcePath}@${sourceCommit} beyond the declared import rewrites`)
    printFirstDiffLine(normalised, sourceText, kitPath)
  } else {
    console.log(`ok   (whole file): ${kitPath} == ${sourcePath}@${sourceCommit}`)
  }
}

/**
 * Exact comparison for a module that was subsetted or had code extracted
 * into a new file (kinds.ts, types.ts, access.ts, channel.ts - see
 * EXTRACTION.md).
 *
 * `chunks` is the ordered, COMPLETE (never truncated) list of verbatim
 * excerpts this file kept from the source, joined with `separator` between
 * them. Two things are checked, together proving the kit's body is made of
 * exactly these excerpts and nothing else:
 *
 *   1. `kitBody` (the kit file's own moved/extracted code - everything
 *      between `bodyStart` and `bodyEnd`, i.e. the kit's added header
 *      comment and, for channel.ts, its own trailing CHANNEL_LABELS export
 *      stripped out) must equal `chunks.join(separator)` EXACTLY. Any body
 *      drift, or any kit-side addition not accounted for by a chunk (such
 *      as a constant nobody remembered to list here), breaks this equality.
 *   2. Each chunk must be found in the pinned source file, in order,
 *      without overlapping the previous match. This is equivalent to
 *      proving the source file, with these matched ranges deleted, is what
 *      was left behind - the parts of the source that did not move.
 *
 * A chunk that is a bare prefix of a declaration (missing its body, as an
 * earlier version of this script had for two access.ts declarations) would
 * pass check 2 trivially and fail check 1 as soon as the kit's real body
 * runs past the prefix - so check 1 alone rules out silently truncated
 * chunks as well as added or drifted content.
 */
function checkExact(kitPath, sourcePath, { bodyStart, bodyEnd, chunks, separator = '\n\n' }) {
  const kitText = readKit(kitPath)
  const sourceText = readAtCommit(sourcePath)

  const startIdx = kitText.indexOf(bodyStart)
  if (startIdx === -1) {
    failures += 1
    console.error(`FAIL (exact): ${kitPath} does not contain its declared bodyStart marker`)
    return
  }
  const bodyFrom = startIdx + bodyStart.length
  const bodyTo = bodyEnd === undefined ? kitText.length : kitText.indexOf(bodyEnd, bodyFrom)
  if (bodyTo === -1) {
    failures += 1
    console.error(`FAIL (exact): ${kitPath} does not contain its declared bodyEnd marker`)
    return
  }
  const kitBody = kitText.slice(bodyFrom, bodyTo).replace(/\n+$/, '')

  const reconstructed = chunks.join(separator)
  let ok = true
  if (kitBody !== reconstructed) {
    ok = false
    failures += 1
    console.error(`FAIL (exact): ${kitPath} body does not equal the declared chunks joined together - added, removed or drifted content`)
    printFirstDiffLine(kitBody, reconstructed, `${kitPath} (kit body vs. reconstructed chunks)`)
  }

  let pos = 0
  for (const [i, chunk] of chunks.entries()) {
    const idx = sourceText.indexOf(chunk, pos)
    if (idx === -1) {
      ok = false
      failures += 1
      console.error(`FAIL (exact): chunk ${i} of ${kitPath} not found verbatim (at or after the previous chunk) in ${sourcePath}@${sourceCommit}: "${chunk.split('\n')[0].slice(0, 60)}..."`)
      continue
    }
    pos = idx + chunk.length
  }

  if (ok) console.log(`ok   (exact, ${chunks.length} chunks): ${kitPath} <-> ${sourcePath}@${sourceCommit}`)
}

function printFirstDiffLine(a, b, label) {
  const aLines = a.split('\n')
  const bLines = b.split('\n')
  for (let i = 0; i < Math.max(aLines.length, bLines.length); i++) {
    if (aLines[i] !== bLines[i]) {
      console.error(`  first differing line ${i + 1} in ${label}:`)
      console.error(`    kit:    ${aLines[i] ?? '<EOF>'}`)
      console.error(`    other:  ${bLines[i] ?? '<EOF>'}`)
      break
    }
  }
}

// --- Whole-file modules (import paths unchanged, or rewritten as noted) ---

for (const f of ['hex.ts', 'verify.ts', 'identity.ts', 'room.ts', 'network-hints.ts', 'display-name.ts', 'link.ts', 'lane.ts']) {
  checkWholeFile(`src/${f}`, `src/${f}`)
}

/**
 * `src/credential.ts` carries exactly two deliberate additions from the
 * pinned source, both part of the forgesworn/kithmoot#205 fix (see
 * EXTRACTION.md "The #205 fix"): the `RestampedCredentialExpiryError` class,
 * and the mint-time check that throws it. Everything else in the file must
 * still be byte-identical, so this strips both declared blocks - and only
 * those blocks, each matched verbatim - before doing the same whole-file
 * comparison every other moved module gets. If either block's text ever
 * drifts from what is declared here, the strip fails to match and the
 * comparison below fails loudly rather than silently accepting unrelated
 * drift.
 */
{
  const KIT_ONLY_BLOCKS = [
    "\n\n/**\n * Thrown by `createDeviceCredential` when a remote signer's restamped\n * `created_at` would make the requested expiry run longer than 30 days from\n * it - see the comment at the throw site, and forgesworn/kithmoot issue 205\n * (CHANGELOG.md has the full writeup and a link).\n * Typed (rather than a plain `Error`) so a caller can distinguish this from\n * the other, unrelated failure modes above it (wrong key, wrong terms, bad\n * signature) and retry with a shorter margin specifically in this case.\n */\nexport class RestampedCredentialExpiryError extends Error {\n  /** How far over the 30-day cap the signed `created_at` pushed the\n   *  requested expiry, in seconds. Always positive. A caller retrying with\n   *  a shorter margin needs to shorten by at least this much. */\n  readonly overBySeconds: number\n  constructor(overBySeconds: number) {\n    super('the signer restamped created_at, and the requested expiry now runs longer than 30 days from it')\n    this.name = 'RestampedCredentialExpiryError'\n    this.overBySeconds = overBySeconds\n  }\n}",
    "\n\n  // forgesworn/kithmoot#205: a remote signer (a bunker, a phone) may restamp\n  // `created_at` to its own, earlier clock. `verifyDeviceCredential` measures\n  // the 30-day cap from the SIGNED `created_at`, not from `now` above - so a\n  // person credential requested near the cap can come back already unable to\n  // verify anywhere (\"longer than 30 days\"), even though nothing here was\n  // asked for more than 30 days. Re-check with the verifier's own\n  // measurement and fail loudly at mint time, rather than handing back a\n  // credential doomed to be refused everywhere it is presented. Callers that\n  // hit this can retry with a shorter `expiresAt` margin.\n  if (person && opts.expiresAt - signed.created_at > PERSON_CREDENTIAL_MAX_SECONDS) {\n    throw new RestampedCredentialExpiryError(opts.expiresAt - signed.created_at - PERSON_CREDENTIAL_MAX_SECONDS)\n  }",
  ]
  const kitText = readKit('src/credential.ts')
  const sourceText = readAtCommit('src/credential.ts')
  let stripped = kitText
  let missing = false
  for (const block of KIT_ONLY_BLOCKS) {
    const idx = stripped.indexOf(block)
    if (idx === -1) {
      failures += 1
      missing = true
      console.error('FAIL (declared diff): src/credential.ts does not contain a declared #205 block verbatim - update diff-source.mjs or restore the block')
      continue
    }
    stripped = stripped.slice(0, idx) + stripped.slice(idx + block.length)
  }
  if (!missing) {
    if (stripped !== sourceText) {
      failures += 1
      console.error('FAIL (whole file, minus declared #205 blocks): src/credential.ts differs from src/credential.ts@' + sourceCommit + ' beyond the declared import rewrites and the #205 blocks')
      printFirstDiffLine(stripped, sourceText, 'src/credential.ts')
    } else {
      console.log(`ok   (whole file, minus declared #205 blocks): src/credential.ts == src/credential.ts@${sourceCommit}`)
    }
  }
}
/**
 * Conference rooms (0.3.0, see EXTRACTION.md "Conference rooms"): a room
 * with a fixed end, carried as a NIP-40 expiration on its group invitation,
 * its retirement and its epoch events. That adds an optional `endsAt` /
 * `expiresAt` to `invitation.ts`, `persistent-invitation.ts` and `epoch.ts`
 * and nothing else: with it absent every event is byte-identical to before.
 *
 * Each declared change is `[kit text, pinned source text, count]`: the kit
 * text must occur exactly `count` times, and is put back to the source text
 * before the usual whole-file comparison. A change that drifts from what is
 * declared here stops matching its count and fails loudly, so nothing else
 * can hide behind it.
 */
const CONFERENCE_CHANGES = {
  "src/epoch.ts": [
    ["\nimport { withExpiration } from './expiration.js'", "", 1],
    ["\n  /** A conference room's end, in unix seconds: the event carries it as a\n   *  NIP-40 expiration (see `withExpiration`). Omit for a room with no end. */\n  expiresAt?: number", "", 3],
    ["tags: withExpiration([", "tags: [", 3],
    ["], opts.expiresAt),", "],", 3],
    ["\n  /** A conference room's end: every grant carries it as an expiration. */\n  expiresAt?: number", "", 1],
    [", refused, expiresAt: opts.expiresAt })", ", refused })", 1],
    ["\n              expiresAt: opts.expiresAt,", "", 1],
    ["\n  /** A conference room's end: the request carries it as an expiration. */\n  expiresAt?: number", "", 1],
    ["\n    expiresAt: opts.expiresAt,", "", 1],
  ],
  "src/invitation.ts": [
    ["\nimport { withExpiration } from './expiration.js'", "", 1],
    ["\n  /** A conference room's end, in unix seconds: the tombstone carries the\n   * same NIP-40 expiration as the invitation it retires, and lapses with it. */\n  endsAt?: number", "", 1],
    ["tags: withExpiration([['d', deriveInvitationId(opts.invitation)]], opts.endsAt),", "tags: [['d', deriveInvitationId(opts.invitation)]],", 1],
  ],
  "src/persistent-invitation.ts": [
    ["\nimport { isRoomEnds, requireRoomEnds } from './expiration.js'", "", 1],
    ["\n  /** When the room ends, in unix seconds: a conference room. Absent for a\n   *  group that runs until somebody ends it. */\n  endsAt?: number", "", 1],
    ["\n  /** A conference room's end, in unix seconds: after `now` and no more than\n   *  30 days beyond it. Carried in the body and as a NIP-40 expiration, so\n   *  relays drop the invitation when the room ends. */\n  endsAt?: number", "", 1],
    ["\n  const ends = opts.endsAt === undefined ? undefined : requireRoomEnds(opts.endsAt, opts.now)", "", 1],
    ["tags: ends === undefined ? [['d', deriveInvitationId(opts.invitation)]] : [['d', deriveInvitationId(opts.invitation)], ['expiration', String(ends)]],", "tags: [['d', deriveInvitationId(opts.invitation)]],", 1],
    ["secret: base64urlnopad.encode(opts.roomSecret), ...(ends === undefined ? {} : { ends }),", "secret: base64urlnopad.encode(opts.roomSecret),", 1],
    ["    // A conference room's end rides in the body and, for relays, as a NIP-40\n    // expiration. The two must agree: a tag with no body end, a second tag,\n    // or an end that is not a whole number of seconds is refused outright.\n    const ends = body.ends === undefined ? undefined : isRoomEnds(body.ends) ? body.ends : null\n    const expirations = event.tags.filter(t => t[0] === 'expiration')\n    if (ends === null || expirations.length > 1) return null\n    if (expirations.length === 1 && (ends === undefined || expirations[0][1] !== String(ends))) return null\n    return ends === undefined ? { secret, persistent: true, epoch: 0 } : { secret, persistent: true, epoch: 0, endsAt: ends }", "    return { secret, persistent: true, epoch: 0 }", 1],
    ["\n        // Two signed copies that disagree on when the room ends: the earlier\n        // end stands, so a stale copy can never keep a room open longer.\n        if (admission?.endsAt !== undefined && (decoded.endsAt === undefined || decoded.endsAt > admission.endsAt)) decoded.endsAt = admission.endsAt", "", 1],
  ],
}

/**
 * Room relays (0.4.0, see EXTRACTION.md "Room relays"): the room's own relays
 * in the group invitation body, after `ends`. Declared the same way, but as
 * 0.4.0 text -> 0.3.0 text, and applied before the conference changes, which
 * then take the 0.3.0 text back to the pinned source as before.
 */
const ROOM_RELAY_CHANGES = {
  "src/persistent-invitation.ts": [
    ["\nimport { isInvitationRelays, requireInvitationRelays } from './invitation-relays.js'", "", 1],
    ["\n  /** The room's own relays, as its inviter signed them: every member's pool\n   *  includes them. Absent from an invitation written before 0.4.0. */\n  relays?: string[]", "", 1],
    ["\n  /** The room's own relays: one to eight distinct safe URLs in canonical\n   *  form (see `isInvitationRelays`), else it throws. Omitted, the body is\n   *  byte-identical to 0.3.0's. */\n  relays?: readonly string[]", "", 1],
    ["\n  const relays = opts.relays === undefined ? undefined : requireInvitationRelays(opts.relays)", "", 1],
    [" ...(ends === undefined ? {} : { ends }), ...(relays === undefined ? {} : { relays }),", " ...(ends === undefined ? {} : { ends }),", 1],
    ["    // The room's relays, when the body names them, must be a list the encoder\n    // would write; a malformed one refuses the envelope rather than half of it.\n    if (body.relays !== undefined && !isInvitationRelays(body.relays)) return null\n    const admission: PersistentRoomAdmission = ends === undefined ? { secret, persistent: true, epoch: 0 } : { secret, persistent: true, epoch: 0, endsAt: ends }\n    if (body.relays !== undefined) admission.relays = [...body.relays]\n    return admission", "    return ends === undefined ? { secret, persistent: true, epoch: 0 } : { secret, persistent: true, epoch: 0, endsAt: ends }", 1],
    ["\n    let relaysAt = -1", "", 1],
    ["\n        // Two signed copies that disagree on the room's relays: the newest\n        // copy that names any stands. A copy naming none (an older writer)\n        // says nothing about them, and on equal timestamps the first heard stays.\n        if (decoded.relays !== undefined && event.created_at > relaysAt) relaysAt = event.created_at\n        else if (admission?.relays !== undefined) decoded.relays = admission.relays", "", 1],
  ],
}

/**
 * Member epoch catch-up (unreleased, see EXTRACTION.md "Member epoch
 * catch-up" and docs/member-epoch-catch-up.md): an optional `commit` on the
 * rekey encoder, written into the body only when asked, and an optional
 * `members` source on `requestRoomEpoch`. With both absent every event is
 * byte-identical to 0.4.0's and the function behaves as before. Declared as
 * new text -> 0.4.0 text and applied first, before the conference changes
 * take the 0.4.0 text back to the pinned source.
 */
const MEMBER_EPOCH_CHANGES = {
  "src/epoch.ts": [
    ["\nimport { epochCommitment } from './epoch-commit.js'", "", 1],
    ["\nimport type { MemberEpochSource } from './member-epoch.js'", "", 1],
    ["\n  /** `epochCommitment(roomId, epoch, secret)`: lets a member hand this epoch\n   *  on and the requester check it. Absent from a rekey written without it. */\n  commit?: string", "", 1],
    ["\n  /** Write the epoch commitment into the body, so any current member can\n   *  bring a device that missed this rekey up to date (see\n   *  `member-epoch.ts`). Omitted, the event is byte-identical to before. */\n  commit?: boolean", "", 1],
    ["\n    ...(opts.commit ? { commit: epochCommitment(roomId, epoch, opts.next.secret) } : {}),", "", 1],
    ["\n  /** Ask the room's current members too (`memberEpochSource`): the first\n   *  answer that checks out, the authority's or a member's, settles it. */\n  members?: MemberEpochSource", "", 1],
    ["\n    let stopMembers = () => {}", "", 1],
    ["\n      stopMembers()\n      settle()", "\n      settle()", 1],
    ["\n    if (opts.members && !settled) {\n      stopMembers = opts.members.start((grant) => finish(() => resolve(grant)))\n      if (settled) stopMembers()\n    }", "", 1],
    // The epochs a member grant carried past, typed on the grant (0.5.1).
    ["  | {\n      epoch: RoomEpoch | { epoch: 0 }\n      removed: string[]\n      /** Present on a member's answer through `requestRoomEpoch({ members })`:\n       *  the epochs it carried between the requester's and `epoch`. See\n       *  `MemberEpochGrant.passed`. The authority's own answer has none. */\n      passed?: RoomEpoch[]\n      refused?: undefined\n    }", "  | { epoch: RoomEpoch | { epoch: 0 }; removed: string[]; refused?: undefined }", 1],
  ],
}

function checkWholeFileWithDeclaredChanges(kitPath, changes, importRewrites) {
  let text = readKit(kitPath)
  for (const [kit, source, count] of changes) {
    const found = text.split(kit).length - 1
    if (found !== count) {
      failures += 1
      console.error(`FAIL (declared change): ${kitPath} carries ${found} (not ${count}) of ${JSON.stringify(kit.trim().split('\n')[0].slice(0, 60))}... - update diff-source.mjs or restore it`)
      return
    }
    text = text.split(kit).join(source)
  }
  for (const [from, to] of importRewrites) text = text.split(from).join(to)
  const sourceText = readAtCommit(kitPath)
  if (text !== sourceText) {
    failures += 1
    console.error(`FAIL (whole file, minus declared changes): ${kitPath} differs from ${kitPath}@${sourceCommit} beyond the declared import rewrites and declared changes`)
    printFirstDiffLine(text, sourceText, kitPath)
  } else {
    console.log(`ok   (whole file, minus ${changes.length} declared changes): ${kitPath} == ${kitPath}@${sourceCommit}`)
  }
}

for (const f of ['invitation.ts', 'persistent-invitation.ts', 'epoch.ts']) {
  checkWholeFileWithDeclaredChanges(`src/${f}`, [...(MEMBER_EPOCH_CHANGES[`src/${f}`] ?? []), ...(ROOM_RELAY_CHANGES[`src/${f}`] ?? []), ...CONFERENCE_CHANGES[`src/${f}`]], [["from './transport.js'", "from './relay-pool.js'"]])
}
checkWholeFile('test/sim-relay.ts', 'test/sim-relay.ts', [["from '../src/transport.js'", "from '../src/relay-pool.js'"]])

// --- Subsetted / extracted modules: exact reconstruction ---

checkExact('src/kinds.ts', 'src/kinds.ts', {
  bodyStart: 'export const KINDS = {\n',
  bodyEnd: '\n} as const',
  separator: '\n',
  chunks: [
    "  /** Device credential. Signed by the participant key; never published to a\n   *  relay - it travels inside the encrypted roster, so relays never see the\n   *  participant pubkey. */\n  CREDENTIAL: 20460,",
    "  /** Chat message, encrypted to the room key and published once, exactly\n   *  like the roster. Unlike the roster this is a DURABLE kind (regular\n   *  event range, not ephemeral) - chat history is the point, so it must\n   *  survive a relay restart and be there for late joiners. */\n  CHAT: 1460,",
    "  /** A prospective member proving possession of a room invitation.\n   *\n   * Ephemeral deliberately: it is a live rendezvous with an inviter, not a\n   * request a relay should retain. The public `d` tag is derived from the\n   * bearer capability; the request body is encrypted under a separate key\n   * derived from that capability. */\n  INVITATION_REQUEST: 20466,",
    "  /** A delegated responder's encrypted response carrying the room traffic\n   * secret and its root-authenticated, room-bound delegation chain. Addressed\n   * to the requester's one-use pubkey; knowing the bearer does not let\n   * somebody nominate a responder or substitute a room. Ephemeral for the\n   * same reason as the request. */\n  INVITATION_GRANT: 20467,",
    "  /** A durable, creator-authenticated tombstone for one invitation.\n   *\n   * Unlike the live request/grant exchange this MUST be a regular stored\n   * event: a delegated responder that was offline when the creator rotated\n   * the link has to learn that fact before it starts answering the old link\n   * again. The invitation id is unique, so one valid retirement is final. */\n  INVITATION_RETIREMENT: 1461,",
    "  /** A persistent group's invitation, signed by the pinned inviter and\n   * encrypted under a separate bearer-derived key. Regular stored event:\n   * newcomers can enter with every member offline. Contains epoch 0 only;\n   * it never grants authority to rekey or bypass a later removal. */\n  GROUP_INVITATION: 1463,",
    "  /** A room moving to a new epoch: a fresh traffic secret, sealed per\n   * remaining device, with the participants removed at this step named.\n   *\n   * Durable, and addressed by the public room id, so a client can find the\n   * room's current epoch from the id alone and know it is behind before it\n   * says anything under a key that is dead. The body is encrypted to the\n   * previous epoch's key, so a relay sees the room id, the epoch number,\n   * the authority's pubkey and a size, and nothing about who was kept or\n   * removed. Signed only by the room's authority, the root inviter pinned\n   * in the link. See `epoch.ts`. */\n  ROOM_REKEY: 1462,",
    "  /** A member that missed a rekey - it was offline, or it is arriving now -\n   * asking the authority for the current epoch, proving which participant it\n   * speaks for with its device credential. Encrypted to the authority and\n   * ephemeral: it is a live handshake, not a record. */\n  EPOCH_REQUEST: 20468,",
    "  /** The authority's answer, sealed to the asking device: the current epoch's\n   * secret and the removed set, or a refusal. Ephemeral for the same reason. */\n  EPOCH_GRANT: 20469,",
  ],
})

checkExact('src/types.ts', 'src/types.ts', {
  bodyStart: 'need it. */\n\n',
  chunks: [
    "/** A device credential is an ordinary signed Nostr event, never published bare. */\nexport type DeviceCredential = Event",
    "/** Kindred tiers, closest first: family, mutual verified bond, one-way\n *  recognition, no requirement at all. */\nexport type AccessTier = 'open' | 'ken' | 'kith' | 'kin'",
    "/** What a room requires of its agents. `owned-by-members`: an agent is\n *  admitted to the roster only with a verified ownership proof from a\n *  participant who is in the room. See `AgentOwnership`. */\nexport type AgentRule = 'owned-by-members'",
    "/** A room's admission rule. `admitted` lists the issuer pubkeys the room\n *  trusts to vouch for guests; irrelevant when `tier` is `open`. `agents`\n *  is a separate rule about what an agent has to show; absent means\n *  nothing, which is how every room worked before it existed. */\nexport interface RoomPolicy {\n  tier: AccessTier\n  admitted?: string[]\n  agents?: AgentRule\n  /** When present, the only participants admitted, whatever the tier\n   *  says. A direct message is a room whose policy lists two. See\n   *  `docs/messages.md`. */\n  members?: string[]\n  /** A quiet room: its chat rides the kind 1059 firehose as dead drops to\n   *  keys derived from the epoch key, on a cadence, so a relay cannot tell\n   *  whether anything was said, by whom, or when. Only with `members`,\n   *  because everybody derives every member's keys. Rides here so that\n   *  everyone who joins agrees on how the room talks, exactly as they\n   *  agree on who may enter. See `quiet.ts`. */\n  quiet?: true\n}",
    "/**\n * A signed claim that `issuer` recognises `participant` at `tier` in `room`,\n * until `expiresAt`. Never issued for `open`, since open needs no proof.\n *\n * `room` is what stops a proof being a bearer token: without it, one proof\n * admits its holder to every room that happens to trust the same issuer, and\n * an issuer who vouched for a guest at one moot has not vouched for them at\n * all of them. The cost of that binding is stated plainly: a kindred proof is\n * a room grant here, not a portable statement about a relationship, so an\n * issuer mints one per room. In this protocol the party who vouches is the\n * party who sent the join link, so it already knows the room id.\n */\nexport type KindredProof = {\n  tier: Exclude<AccessTier, 'open'>\n  participant: string\n  issuer: string\n  /** The room id this proof is valid in. */\n  room: string\n  /** 32 random bytes, hex, unique to this proof. Signed over, so two proofs\n   *  on identical terms are still distinguishable - which is what a revocation\n   *  list, or an audit, needs to name one of them. */\n  nonce: string\n  sig: string\n  expiresAt: number\n}",
  ],
})

checkExact('src/access.ts', 'src/access.ts', {
  bodyStart: "import type { KindredProof, RoomPolicy } from './types.js'\n\n",
  chunks: [
    "/** Closest first, matching the canonical order in the kindred primitive. */\nconst TIER_RANK: Record<string, number | undefined> = { kin: 3, kith: 2, ken: 1, open: 0 }",
    "/**\n * The exact bytes a kindred proof signs over. Every field that changes the\n * proof's meaning is in here, so tampering with any one of them - tier,\n * subject, room, nonce or expiry - invalidates the signature.\n *\n * `room` and `nonce` are covered deliberately: see `KindredProof`. A proof\n * signed by an implementation that omits them reconstructs a different message\n * and fails the signature check, which is the right way round - an older proof\n * is refused rather than silently admitted somewhere it was never meant to go.\n */\nfunction canonicalMessage(\n  tier: KindredProof['tier'],\n  participant: string,\n  room: string,\n  nonce: string,\n  expiresAt: number,\n): Uint8Array {\n  return sha256(\n    new TextEncoder().encode(`kithmoot/v1/kindred:${tier}:${participant}:${room}:${nonce}:${expiresAt}`),\n  )\n}",
    "export interface IssueKindredProofOptions {\n  /** The issuer's secret key. */\n  hostSk: Uint8Array\n  participant: string\n  tier: KindredProof['tier']\n  /** The room this proof admits the participant to. */\n  roomId: string\n  /** Unix seconds. */\n  expiresAt: number\n  /** 32 bytes, hex. Supply one only to make a proof reproducible - the\n   *  interop vectors do; everything else wants the random default. */\n  nonce?: string\n}",
    "/** Vouch for a participant at a tier, in one room, until an expiry. */\nexport function issueKindredProof(opts: IssueKindredProofOptions): KindredProof {\n  // `participant` and `roomId` are identifiers handed in by the caller -\n  // possibly typed or pasted - so they are canonicalised here, at the point\n  // they enter the proof, rather than left for `evaluateAccess`'s equality\n  // checks to paper over.\n  const participant = normaliseHex(opts.participant)\n  const room = normaliseHex(opts.roomId)\n  const nonce = normaliseHex(opts.nonce ?? bytesToHex(randomBytes(32)))\n  const sig = schnorr.sign(canonicalMessage(opts.tier, participant, room, nonce, opts.expiresAt), opts.hostSk)\n  return {\n    tier: opts.tier,\n    participant,\n    issuer: getPublicKey(opts.hostSk),\n    room,\n    nonce,\n    sig: bytesToHex(sig),\n    expiresAt: opts.expiresAt,\n  }\n}",
    "/**\n * Decide whether `participant` may join a room under `policy`.\n *\n * `ken` is one-way recognition - pinning someone's key from an authoritative\n * source, with no bond back - so it never satisfies a `kith` gate. `kin` is\n * closer than `kith` and does. Checks run cheapest first and never throw:\n * participant match, room match, expiry, issuer trust, tier, then the schnorr\n * verification last, since it is the most expensive.\n */\nexport function evaluateAccess(\n  policy: RoomPolicy,\n  participant: string,\n  proof: KindredProof | undefined,\n  now: number,\n  roomId: string,\n): { admitted: boolean; reason: string } {\n  // A members list closes the door before any tier is considered: a\n  // direct message is open in tier and shut to everybody but its two.\n  if (policy.members !== undefined && !policy.members.some((m) => hexEquals(m, participant))) {\n    return { admitted: false, reason: 'not a member' }\n  }\n  if (policy.tier === 'open') return { admitted: true, reason: 'open room' }\n  if (!proof) return { admitted: false, reason: 'no kindred proof' }\n  // Hex, compared case-insensitively throughout this function: see\n  // `hexEquals` and `vectors/README.md`. An allow-list entry, or a proof,\n  // stored in upper-case hex names exactly the same identifier and must not\n  // be rejected on case alone.\n  if (!hexEquals(proof.participant, participant)) return { admitted: false, reason: 'proof names another participant' }\n  // A proof is a grant in one room, not a bearer token - see `KindredProof`.\n  if (proof.room === undefined || !hexEquals(proof.room, roomId)) {\n    return { admitted: false, reason: 'proof names another room' }\n  }\n  if (proof.expiresAt <= now) return { admitted: false, reason: 'expired' }\n  if (!policy.admitted?.some((a) => hexEquals(a, proof.issuer))) {\n    return { admitted: false, reason: 'untrusted issuer' }\n  }\n\n  // Fail closed on a tier we do not recognise. TIER_RANK[unknown] is\n  // undefined and `undefined < 2` is false, so the obvious comparison skips\n  // the rejection branch and admits - the opposite of what a gate is for. A\n  // trusted issuer's typo, or a looser independent implementation, is all it\n  // would take.\n  const rank = TIER_RANK[proof.tier]\n  if (rank === undefined) return { admitted: false, reason: 'unrecognised tier' }\n  if (rank < (TIER_RANK[policy.tier] ?? 0)) return { admitted: false, reason: 'tier too low' }\n\n  try {\n    const message = canonicalMessage(proof.tier, proof.participant, proof.room, proof.nonce, proof.expiresAt)\n    if (!schnorr.verify(hexToBytes(proof.sig), message, hexToBytes(proof.issuer))) {\n      return { admitted: false, reason: 'bad signature' }\n    }\n  } catch {\n    return { admitted: false, reason: 'bad signature' }\n  }\n\n  return { admitted: true, reason: 'kindred proof accepted' }\n}",
    "/** Every wire-format literal this module owns (each one a kithmoot protocol string), frozen for\n *  `src/labels.test.ts`, which checks each module against its own exported\n *  list rather than scanning file text for matching comments. Pure data -\n *  adding this export changes no runtime behaviour. */\nexport const ACCESS_LABELS = [\n  \"kithmoot/v1/kindred:\",\n] as const",
  ],
})

// channel.ts: the body proven exact here is the moved code - CHANNEL_ID_INFO,
// CHANNEL_KEY_INFO, MAX_CHANNEL_NAME_LENGTH and deriveChannel. The trailing
// CHANNEL_LABELS export is not: it is the same array of two label strings as
// source's CHAT_LABELS, deliberately renamed (see EXTRACTION.md) because the
// export now lives in its own file - a rename cannot be proven "identical to
// source" by definition, so it is checked separately, on values, below.
checkExact('src/channel.ts', 'src/chat.ts', {
  bodyStart: 'codecs stay in KithMoot. */\n\n',
  bodyEnd: '\n\n/** Every wire-format literal this module owns',
  chunks: [
    "export const CHANNEL_ID_INFO = 'kithmoot/v1/channel-id/'\nexport const CHANNEL_KEY_INFO = 'kithmoot/v1/channel-key/'\n/** Bounds a channel name, which rides only in an HKDF info string and\n *  never on the wire; long enough for any sensible name. */\nexport const MAX_CHANNEL_NAME_LENGTH = 64",
    "/**\n * The room id and key a named channel lives under.\n *\n * Both derived from the room KEY, never the room id, so a party that holds\n * the id and not the key - a forwarder, a relay - cannot find the channel\n * from the room, let alone read it. Two separate HKDF expansions for the\n * same reason `deriveRoom` uses two: publishing the id reveals nothing about\n * the key. The main chat is the unnamed channel and is untouched by this:\n * its id is the room id and its key the room key, byte for byte as before.\n */\nexport function deriveChannel(roomId: string, roomKey: Uint8Array, channel?: string): { id: string; key: Uint8Array } {\n  if (channel === undefined) return { id: roomId, key: roomKey }\n  if (channel.length === 0 || channel.length > MAX_CHANNEL_NAME_LENGTH) throw new Error('channel name out of range')\n  const idBytes = hkdf(sha256, roomKey, undefined, CHANNEL_ID_INFO + channel, 32)\n  const key = hkdf(sha256, roomKey, undefined, CHANNEL_KEY_INFO + channel, 32)\n  const id = Array.from(idBytes, (b) => b.toString(16).padStart(2, '0')).join('')\n  return { id, key }\n}",
  ],
})

/** channel.ts's CHANNEL_LABELS is a deliberate rename of chat.ts's
 *  CHAT_LABELS (see the comment above); this checks the label VALUES it
 *  carries are still exactly source's two channel label strings. */
function checkLabelArrayValues(kitPath, kitConstName, sourcePath, sourceConstName) {
  const kitText = readKit(kitPath)
  const sourceText = readAtCommit(sourcePath)
  const kitMatch = kitText.match(new RegExp(`export const ${kitConstName} = \\[([\\s\\S]*?)\\] as const`))
  const sourceMatch = sourceText.match(new RegExp(`export const ${sourceConstName} = \\[([\\s\\S]*?)\\] as const`))
  if (!kitMatch) {
    failures += 1
    console.error(`FAIL (labels): ${kitConstName} not found in ${kitPath}`)
    return
  }
  if (!sourceMatch) {
    failures += 1
    console.error(`FAIL (labels): ${sourceConstName} not found in ${sourcePath}@${sourceCommit}`)
    return
  }
  if (kitMatch[1].trim() !== sourceMatch[1].trim()) {
    failures += 1
    console.error(`FAIL (labels): ${kitPath}'s ${kitConstName} values differ from ${sourcePath}@${sourceCommit}'s ${sourceConstName}`)
    printFirstDiffLine(kitMatch[1].trim(), sourceMatch[1].trim(), `${kitConstName} vs ${sourceConstName}`)
    return
  }
  console.log(`ok   (label values): ${kitPath}'s ${kitConstName} == ${sourcePath}@${sourceCommit}'s ${sourceConstName}`)
}

checkLabelArrayValues('src/channel.ts', 'CHANNEL_LABELS', 'src/chat.ts', 'CHAT_LABELS')

/** Guards against content appended after `afterMarker` that no check above
 *  would ever see (checkExact's channel.ts bodyEnd stops before
 *  CHANNEL_LABELS, and checkLabelArrayValues only reads inside its array) -
 *  asserts nothing but whitespace follows it. */
function checkNoTrailingContent(kitPath, afterMarker) {
  const kitText = readKit(kitPath)
  const idx = kitText.indexOf(afterMarker)
  if (idx === -1) {
    failures += 1
    console.error(`FAIL (trailing): ${kitPath} does not contain its declared afterMarker`)
    return
  }
  const trailing = kitText.slice(idx + afterMarker.length)
  if (trailing.trim().length > 0) {
    failures += 1
    console.error(`FAIL (trailing): ${kitPath} has unaccounted-for content after ${JSON.stringify(afterMarker)}: ${JSON.stringify(trailing.slice(0, 80))}`)
    return
  }
  console.log(`ok   (trailing): ${kitPath} has nothing after ${JSON.stringify(afterMarker)} but whitespace`)
}

checkNoTrailingContent('src/channel.ts', '] as const')

if (failures > 0) {
  console.error(`\ndiff-source: ${failures} difference(s) found against ${sourceCommit}`)
  process.exit(1)
}
console.log(`\ndiff-source: zero differences against ${sourceCommit}`)
