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

/** Grant publication acknowledgement: transport settlement changes local
 * callbacks only. Request/grant encoders and envelope versions are unchanged.
 * Undo the two exact declared hunks before checking the extracted source. */
const GRANT_PUBLICATION_CHANGES = {
  "src/invitation.ts": [
    [
      "  now?: () => number\n  /** Called after the injected transport acknowledges publication. This is\n   * not proof that the guest received the grant or joined the room. */\n  onAdmitted?: (device: string) => void\n  /** The same publication acknowledgement, correlated to the request. */\n  onGrantPublished?: (request: InvitationRequest) => void\n  /** Publication rejected or threw. No admission callback is made. */\n  onGrantFailed?: (request: InvitationRequest, error: unknown) => void\n  /** Called when the creator's durable retirement tombstone is heard. */\n",
      "  now?: () => number\n  onAdmitted?: (device: string) => void\n  /** Called when the creator's durable retirement tombstone is heard. */\n",
      1
    ],
    [
      "        }\n        // The decision to approve and the publication of its grant are\n        // separate states. A rejected send must never look like admission.\n        Promise.resolve()\n          .then(() => { if (!closed) return opts.transport.publish(grant) })\n          .then(() => {\n            if (closed) return\n            // One observer throwing must not change the publish outcome or\n            // prevent an independent observer from hearing it.\n            try { opts.onGrantPublished?.(request) } catch { /* Observer only. */ }\n            try { opts.onAdmitted?.(request.device) } catch { /* Observer only. */ }\n          }, error => {\n            if (!closed) opts.onGrantFailed?.(request, error)\n          })\n          .catch(() => { /* A failure observer cannot escape the relay loop. */ })\n      }\n",
      "        }\n        opts.transport.publish(grant).catch(() => {})\n        opts.onAdmitted?.(request.device)\n      }\n",
      1
    ]
  ]
}

/**
 * Self-destructing rooms (0.9.0, see docs/room-destruct.md): an optional
 * `destruct: true` in the group invitation body, beside `ends`, in an ended
 * room's retirement, and in a closing rekey's body, each surfaced on its
 * reader. With the flag absent every event is byte-identical to 0.8.0's.
 * Declared as 0.9.0 text -> 0.8.0 text, generated hunk by hunk from the
 * diff with one line of context, and applied before every other change set.
 */
const DESTRUCT_CHANGES = {
  "src/invitation.ts": [
    ["  ended?: boolean\n  /** The ended room self-destructs: every device deletes what it wrote and\n   * forgets the room. Only beside `ended`, else it throws. Unlike the\n   * invitation's own flag this content is not encrypted: it says no more\n   * than `ended` does about a link nobody outside the room can name.\n   * Omitted or false, the event is byte-identical to 0.8.0's. */\n  destruct?: boolean\n  /** A conference room's end, in unix seconds: the tombstone carries the", "  ended?: boolean\n  /** A conference room's end, in unix seconds: the tombstone carries the", 1],
    ["  }\n  if (opts.destruct && !opts.ended) throw new Error('only an ended room can self-destruct')\n  return finalizeEvent(", "  }\n  return finalizeEvent(", 1],
    ["      tags: withExpiration([['d', deriveInvitationId(opts.invitation)]], opts.endsAt),\n      content: JSON.stringify(opts.ended ? (opts.destruct ? { v: 1, ended: true, destruct: true } : { v: 1, ended: true }) : { v: 1 }),\n    },", "      tags: withExpiration([['d', deriveInvitationId(opts.invitation)]], opts.endsAt),\n      content: JSON.stringify(opts.ended ? { v: 1, ended: true } : { v: 1 }),\n    },", 1],
    ["\n/** A valid retirement, whether it says the room was ended, and whether the\n * ended room self-destructs (`destruct`, believed only beside `ended`).\n * Undefined for anything that is not a valid retirement of this invitation. */\nexport function decodeInvitationRetirementNotice(event: Event, invitation: RoomInvitation): { ended: boolean; destruct?: true } | undefined {\n  try {", "\n/** A valid retirement, and whether it says the room was ended. Undefined\n * for anything that is not a valid retirement of this invitation. */\nexport function decodeInvitationRetirementNotice(event: Event, invitation: RoomInvitation): { ended: boolean } | undefined {\n  try {", 1],
    ["    if (event.tags.find((tag) => tag[0] === 'd')?.[1] !== deriveInvitationId(invitation)) return undefined\n    const body = JSON.parse(event.content) as { v?: unknown; ended?: unknown; destruct?: unknown }\n    if (body.v !== 1) return undefined\n    return body.ended === true && body.destruct === true ? { ended: true, destruct: true } : { ended: body.ended === true }\n  } catch {", "    if (event.tags.find((tag) => tag[0] === 'd')?.[1] !== deriveInvitationId(invitation)) return undefined\n    const body = JSON.parse(event.content) as { v?: unknown; ended?: unknown }\n    return body.v === 1 ? { ended: body.ended === true } : undefined\n  } catch {", 1],
  ],
  "src/persistent-invitation.ts": [
    ["  relays?: string[]\n  /** The room self-destructs: when it ends, every device deletes what it\n   *  wrote and forgets the room. Absent for a room that simply ends. */\n  destruct?: true\n}", "  relays?: string[]\n}", 1],
    ["  relays?: readonly string[]\n  /** The room self-destructs when it ends, by its time or by its authority\n   *  closing it. Written inside the encrypted body only, never as a tag.\n   *  Omitted or false, the event is byte-identical to 0.8.0's. */\n  destruct?: boolean\n}): Event {", "  relays?: readonly string[]\n}): Event {", 1],
    ["    content: nip44.v2.encrypt(JSON.stringify({\n      v: 3, room, secret: base64urlnopad.encode(opts.roomSecret), ...(ends === undefined ? {} : { ends }), ...(opts.destruct ? { destruct: true } : {}), ...(relays === undefined ? {} : { relays }),\n    }), welcomeKey(opts.invitation)),", "    content: nip44.v2.encrypt(JSON.stringify({\n      v: 3, room, secret: base64urlnopad.encode(opts.roomSecret), ...(ends === undefined ? {} : { ends }), ...(relays === undefined ? {} : { relays }),\n    }), welcomeKey(opts.invitation)),", 1],
    ["    if (body.relays !== undefined && !isInvitationRelays(body.relays)) return null\n    // Self-destruct is `true` or absent; anything else is a malformed\n    // envelope, refused as a malformed end is.\n    if (body.destruct !== undefined && body.destruct !== true) return null\n    const admission: PersistentRoomAdmission = ends === undefined ? { secret, persistent: true, epoch: 0 } : { secret, persistent: true, epoch: 0, endsAt: ends }\n    if (body.relays !== undefined) admission.relays = [...body.relays]\n    if (body.destruct === true) admission.destruct = true\n    return admission", "    if (body.relays !== undefined && !isInvitationRelays(body.relays)) return null\n    const admission: PersistentRoomAdmission = ends === undefined ? { secret, persistent: true, epoch: 0 } : { secret, persistent: true, epoch: 0, endsAt: ends }\n    if (body.relays !== undefined) admission.relays = [...body.relays]\n    return admission", 1],
    ["        if (admission?.endsAt !== undefined && (decoded.endsAt === undefined || decoded.endsAt > admission.endsAt)) decoded.endsAt = admission.endsAt\n        // Two signed copies that disagree on self-destruct: it sticks, for\n        // the same reason, so a stale copy can never keep a room's content.\n        if (admission?.destruct) decoded.destruct = true\n        // Two signed copies that disagree on the room's relays: the newest", "        if (admission?.endsAt !== undefined && (decoded.endsAt === undefined || decoded.endsAt > admission.endsAt)) decoded.endsAt = admission.endsAt\n        // Two signed copies that disagree on the room's relays: the newest", 1],
  ],
  "src/epoch.ts": [
    ["  closed?: true\n  /** The closed room self-destructs. Written only beside `closed`, and not\n   *  believed without it. */\n  destruct?: true\n  /** A turn of the key on the room's schedule: nobody was removed and the", "  closed?: true\n  /** A turn of the key on the room's schedule: nobody was removed and the", 1],
    ["  closed?: boolean\n  /** The room being closed self-destructs: every device deletes what it\n   *  wrote and forgets the room. Inside the encrypted body. Refused\n   *  without `closed`. Omitted, the event is byte-identical to before. */\n  destruct?: boolean\n  /** Mark this as a scheduled turn of the key rather than a removal, so", "  closed?: boolean\n  /** Mark this as a scheduled turn of the key rather than a removal, so", 1],
    ["  if (opts.scheduled && (removed.length > 0 || opts.closed)) throw new Error('a scheduled rekey removes nobody and does not close the room')\n  if (opts.destruct && !opts.closed) throw new Error('only a closing rekey can self-destruct the room')\n  const keys: Record<string, string> = {}", "  if (opts.scheduled && (removed.length > 0 || opts.closed)) throw new Error('a scheduled rekey removes nobody and does not close the room')\n  const keys: Record<string, string> = {}", 1],
    ["    ...(opts.closed ? { closed: true } : {}),\n    ...(opts.destruct ? { destruct: true } : {}),\n    ...(opts.scheduled ? { scheduled: true } : {}),", "    ...(opts.closed ? { closed: true } : {}),\n    ...(opts.scheduled ? { scheduled: true } : {}),", 1],
    ["  closed: boolean\n  /** True when the closed room self-destructs. Absent unless `closed`:\n   *  beside an open room the flag is not believed, and the rekey is read\n   *  as if it were not there. */\n  destruct?: true\n  /** True for a scheduled turn of the key: nobody removed, the room still", "  closed: boolean\n  /** True for a scheduled turn of the key: nobody removed, the room still", 1],
    ["    if (typeof body.by === 'string' && HEX64.test(body.by)) notice.by = normaliseHex(body.by)\n    if (body.destruct === true && notice.closed) notice.destruct = true\n    if (body.scheduled === true && notice.removed.length === 0 && !notice.closed) notice.scheduled = true", "    if (typeof body.by === 'string' && HEX64.test(body.by)) notice.by = normaliseHex(body.by)\n    if (body.scheduled === true && notice.removed.length === 0 && !notice.closed) notice.scheduled = true", 1],
  ],
}

/**
 * Scheduled rekeys (0.8.0, see docs/scheduled-rekey.md): a `scheduled`
 * marker in the rekey body, the history window (`HISTORY_WINDOW_SECONDS`,
 * `MAX_HISTORY_EPOCHS`, `epochsInWindow`), and the window's left epochs in
 * the authority's grant (`passed`, `HostRoomEpochOptions.past`). A rekey
 * without the marker, and a grant without `passed`, is byte-identical to
 * 0.7.0's. Declared as 0.8.0 text -> 0.7.0 text, generated hunk by hunk from
 * the diff with one line of context, and applied after `DESTRUCT_CHANGES`
 * and before `SEAL_CHANGES`.
 */
const SCHEDULE_CHANGES = {
  "src/epoch.ts": [
    ["  closed?: true\n  /** A turn of the key on the room's schedule: nobody was removed and the\n   *  room stays open, so a client need not announce it. Never written\n   *  beside a removal or a close, and not believed beside one. */\n  scheduled?: true\n  /** `epochCommitment(roomId, epoch, secret)`: lets a member hand this epoch", "  closed?: true\n  /** `epochCommitment(roomId, epoch, secret)`: lets a member hand this epoch", 1],
    ["  closed?: boolean\n  /** Mark this as a scheduled turn of the key rather than a removal, so\n   *  clients can let it pass quietly. Refused with a removal or a close: a\n   *  rekey that removes somebody is never quiet. Omitted, the event is\n   *  byte-identical to before. */\n  scheduled?: boolean\n  /** Write the epoch commitment into the body, so any current member can", "  closed?: boolean\n  /** Write the epoch commitment into the body, so any current member can", 1],
    ["  const removed = [...new Set(opts.removed.map((p) => requireHex32(p, 'removed participant')))].sort()\n  if (opts.scheduled && (removed.length > 0 || opts.closed)) throw new Error('a scheduled rekey removes nobody and does not close the room')\n  const keys: Record<string, string> = {}", "  const removed = [...new Set(opts.removed.map((p) => requireHex32(p, 'removed participant')))].sort()\n  const keys: Record<string, string> = {}", 1],
    ["    ...(opts.closed ? { closed: true } : {}),\n    ...(opts.scheduled ? { scheduled: true } : {}),\n    ...(opts.commit ? { commit: epochCommitment(roomId, epoch, opts.next.secret) } : {}),", "    ...(opts.closed ? { closed: true } : {}),\n    ...(opts.commit ? { commit: epochCommitment(roomId, epoch, opts.next.secret) } : {}),", 1],
    ["  closed: boolean\n  /** True for a scheduled turn of the key: nobody removed, the room still\n   *  open. What lets a client move on without saying so. Absent when the\n   *  body contradicts itself, so a removal is always announced. */\n  scheduled?: true\n  /** The new secret, when a copy was sealed for this device. Absent for a", "  closed: boolean\n  /** The new secret, when a copy was sealed for this device. Absent for a", 1],
    ["    if (typeof body.by === 'string' && HEX64.test(body.by)) notice.by = normaliseHex(body.by)\n    if (body.scheduled === true && notice.removed.length === 0 && !notice.closed) notice.scheduled = true\n    const members = readMemberList(body.members)", "    if (typeof body.by === 'string' && HEX64.test(body.by)) notice.by = normaliseHex(body.by)\n    const members = readMemberList(body.members)", 1],
    ["\n// ---------------------------------------------------------------------------\n// The history window\n// ---------------------------------------------------------------------------\n\n/** How long a member goes on reading an epoch the room has left: 30 days,\n *  as long as a chat log keeps a message. */\nexport const HISTORY_WINDOW_SECONDS = 30 * 86_400\n/** The most left epochs a member goes on reading, and an authority's grant\n *  hands over, however many fall inside the window. A weekly schedule puts\n *  about five in it; removals are what push it higher. Not\n *  `MAX_MEMBER_EPOCH_CHAIN`, which bounds how far behind a member desk will\n *  bring somebody. */\nexport const MAX_HISTORY_EPOCHS = 16\n\n/** An epoch the room has moved past, and when. */\nexport interface LeftEpoch extends RoomEpoch {\n  /** When the room left it, in unix seconds: the `created_at` of the rekey\n   *  out of it. */\n  leftAt: number\n}\n\n/**\n * The left epochs still read at `now`: those left within\n * `HISTORY_WINDOW_SECONDS` (one left exactly that long ago is kept), newest\n * first, one per epoch number (the first given), at most\n * `MAX_HISTORY_EPOCHS`. Every client applies the same rule, so what an\n * authority hands over is what a member goes on reading. Pure, and never\n * throws: an entry with no usable number or time is dropped.\n */\nexport function epochsInWindow<T extends { epoch: number; leftAt: number }>(left: readonly T[], now: number): T[] {\n  const since = now - HISTORY_WINDOW_SECONDS\n  const usable = left.filter(\n    (e) => typeof e === 'object' && e !== null && Number.isSafeInteger(e.epoch) && e.epoch >= 0 && Number.isFinite(e.leftAt) && e.leftAt >= since,\n  )\n  const seen = new Set<number>()\n  const out: T[] = []\n  for (const e of usable.sort((a, b) => b.epoch - a.epoch)) {\n    if (seen.has(e.epoch)) continue\n    seen.add(e.epoch)\n    out.push(e)\n    if (out.length === MAX_HISTORY_EPOCHS) break\n  }\n  return out\n}\n\n// ---------------------------------------------------------------------------", "\n// ---------------------------------------------------------------------------", 1],
    ["\n/** A left epoch as a grant carries it. */\ninterface PassedEpochBody {\n  epoch: number\n  /** base64url, like the grant's own secret. */\n  secret: string\n  /** `LeftEpoch.leftAt`. */\n  left: number\n}\n\ninterface EpochGrantBody {", "\ninterface EpochGrantBody {", 1],
    ["  members?: string[]\n  /** The window's left epochs, oldest first. Absent when there are none. */\n  passed?: PassedEpochBody[]\n  refused?: EpochRefusal", "  members?: string[]\n  refused?: EpochRefusal", 1],
    ["  members?: string[]\n  /**\n   * The epochs the room has left that are still read (`epochsInWindow`),\n   * so a newcomer, or a device back after missing several rekeys, reads\n   * the last month and not only the current epoch. Each is after epoch 0,\n   * whose secret is the room secret and is never handed over, and before\n   * `epoch`; at most `MAX_HISTORY_EPOCHS`, each once. Omitted or empty,\n   * the body is as before.\n   */\n  passed?: readonly LeftEpoch[]\n  refused?: EpochRefusal", "  members?: string[]\n  refused?: EpochRefusal", 1],
    ["\nfunction passedListOf(passed: readonly LeftEpoch[], granted: number): PassedEpochBody[] {\n  if (passed.length > MAX_HISTORY_EPOCHS) throw new Error(`a grant carries at most ${MAX_HISTORY_EPOCHS} passed epochs`)\n  const out = passed\n    .map((e) => {\n      const epoch = requireEpochNumber(e.epoch)\n      if (epoch < 1 || epoch >= granted) throw new Error('a passed epoch comes after epoch 0 and before the one granted')\n      require32(e.secret, 'epoch secret')\n      if (!Number.isSafeInteger(e.leftAt) || e.leftAt < 0) throw new Error('leftAt must be a non-negative integer')\n      return { epoch, secret: base64urlnopad.encode(e.secret), left: e.leftAt }\n    })\n    .sort((a, b) => a.epoch - b.epoch)\n  for (let i = 1; i < out.length; i += 1) {\n    if (out[i]!.epoch === out[i - 1]!.epoch) throw new Error('a passed epoch is listed once')\n  }\n  return out\n}\n\n/** A grant's passed epochs, or undefined unless every entry is in the form\n *  `encodeEpochGrant` writes. One bad entry costs the history, not the\n *  grant: the current epoch still stands. */\nfunction readPassedList(raw: unknown, granted: number): Array<RoomEpoch & { leftAt: number }> | undefined {\n  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_HISTORY_EPOCHS) return undefined\n  const out: Array<RoomEpoch & { leftAt: number }> = []\n  for (const entry of raw) {\n    if (typeof entry !== 'object' || entry === null) return undefined\n    const { epoch, secret, left } = entry as Partial<PassedEpochBody>\n    if (!Number.isSafeInteger(epoch) || (epoch as number) < 1 || (epoch as number) >= granted) return undefined\n    if (out.length > 0 && (epoch as number) <= out[out.length - 1]!.epoch) return undefined\n    if (typeof secret !== 'string' || !Number.isSafeInteger(left) || (left as number) < 0) return undefined\n    let bytes: Uint8Array\n    try {\n      bytes = base64urlnopad.decode(secret)\n    } catch {\n      return undefined\n    }\n    if (bytes.length !== 32) return undefined\n    out.push({ epoch: epoch as number, secret: bytes, leftAt: left as number })\n  }\n  return out\n}\n\n/** Answer one request: the current epoch sealed to the asking device, or a", "\n/** Answer one request: the current epoch sealed to the asking device, or a", 1],
    ["    if (opts.members !== undefined) body.members = memberListOf(opts.members, body.removed)\n    if (opts.passed !== undefined && opts.passed.length > 0) body.passed = passedListOf(opts.passed, body.epoch)\n  }", "    if (opts.members !== undefined) body.members = memberListOf(opts.members, body.removed)\n  }", 1],
    ["      removed: string[]\n      /** Earlier epochs handed over with `epoch`, oldest first. A member's\n       *  answer through `requestRoomEpoch({ members })` carries the epochs\n       *  between the requester's and `epoch` (see `MemberEpochGrant.passed`);\n       *  the authority's carries the window's (`EncodeEpochGrantOptions.passed`),\n       *  when its desk was given them. `leftAt` is when the room left each,\n       *  when the answer said. */\n      passed?: Array<RoomEpoch & { leftAt?: number }>\n      /** The participants the room knows, when the answer carried them. */", "      removed: string[]\n      /** Present on a member's answer through `requestRoomEpoch({ members })`:\n       *  the epochs it carried between the requester's and `epoch`. See\n       *  `MemberEpochGrant.passed`. The authority's own answer has none. */\n      passed?: RoomEpoch[]\n      /** The participants the room knows, when the answer carried them. */", 1],
    ["    if (secret.length !== 32) return null\n    const passed = readPassedList(body.passed, body.epoch as number)\n    return { epoch: { epoch: body.epoch as number, secret }, removed, ...listed, ...(passed ? { passed } : {}) }\n  } catch {", "    if (secret.length !== 32) return null\n    return { epoch: { epoch: body.epoch as number, secret }, removed, ...listed }\n  } catch {", 1],
    ["  members?: () => readonly string[]\n  /**\n   * The epochs the room has left, with their secrets and when it left\n   * each: every grant carries those still in the window, so a newcomer\n   * reads the last month as a returning member does. Asked on every grant.\n   * Whatever a grant could not carry (epoch 0, an epoch not before the\n   * current one, a bad secret) is left out rather than costing the grant.\n   */\n  past?: () => readonly LeftEpoch[]\n  /**", "  members?: () => readonly string[]\n  /**", 1],
    ["\n/** What a desk hands over of `past()`: the window's epochs below the one it\n *  grants, leaving out anything `encodeEpochGrant` would refuse, so a bad\n *  entry costs the history and never the grant. */\nfunction passedFor(past: (() => readonly LeftEpoch[]) | undefined, granted: number, now: number): LeftEpoch[] {\n  if (!past) return []\n  let given: readonly LeftEpoch[]\n  try {\n    given = past()\n  } catch {\n    return []\n  }\n  if (!Array.isArray(given)) return []\n  const carried = given.filter(\n    (e) =>\n      typeof e === 'object' &&\n      e !== null &&\n      Number.isSafeInteger(e.epoch) &&\n      e.epoch >= 1 &&\n      e.epoch < granted &&\n      e.secret instanceof Uint8Array &&\n      e.secret.length === 32 &&\n      Number.isSafeInteger(e.leftAt) &&\n      e.leftAt >= 0,\n  )\n  return epochsInWindow(carried, now)\n}\n\n/**", "\n/**", 1],
    ["      try {\n        if (refused) {\n          grant = encodeEpochGrant({\n            roomId,\n            authoritySk: opts.authoritySk,\n            device: request.device,\n            request: request.request,\n            now: now(),\n            refused,\n            credential: sealCredential(request, read.credential, opts.credentialFor, roomId, now()),\n            expiresAt: opts.expiresAt,\n          })\n        } else {\n          const epoch = opts.current()\n          grant = encodeEpochGrant({\n            roomId,\n            authoritySk: opts.authoritySk,\n            device: request.device,\n            request: request.request,\n            now: now(),\n            epoch,\n            removed: [...opts.removed()],\n            ...(opts.members ? { members: [...opts.members()] } : {}),\n            ...(opts.past ? { passed: passedFor(opts.past, epoch.epoch, now()) } : {}),\n            credential: sealCredential(request, read.credential, opts.credentialFor, roomId, now()),\n            expiresAt: opts.expiresAt,\n          })\n        }\n      } catch {", "      try {\n        grant = refused\n          ? encodeEpochGrant({\n              roomId,\n              authoritySk: opts.authoritySk,\n              device: request.device,\n              request: request.request,\n              now: now(),\n              refused,\n              credential: sealCredential(request, read.credential, opts.credentialFor, roomId, now()),\n              expiresAt: opts.expiresAt,\n            })\n          : encodeEpochGrant({\n              roomId,\n              authoritySk: opts.authoritySk,\n              device: request.device,\n              request: request.request,\n              now: now(),\n              epoch: opts.current(),\n              removed: [...opts.removed()],\n              ...(opts.members ? { members: [...opts.members()] } : {}),\n              credential: sealCredential(request, read.credential, opts.credentialFor, roomId, now()),\n              expiresAt: opts.expiresAt,\n            })\n      } catch {", 1],
  ],
}

/**
 * Seal keys (0.7.0, see docs/seal-key.md): a credential may name the
 * device's seal key, and rekeys and epoch grants are sealed to it instead of
 * the device key. With no seal key anywhere every event is byte-identical to
 * 0.6.0's. Declared as 0.7.0 text -> 0.6.0 text, generated hunk by hunk from
 * the diff with one line of context, and applied after `SCHEDULE_CHANGES`
 * and before everything else.
 */
const SEAL_CHANGES = {
  "src/credential.ts": [
    ["import type { DeviceCredential } from './types.js'\nimport { isSealPubkey, SEAL_TAG } from './seal.js'\n", "import type { DeviceCredential } from './types.js'\n", 1],
    ["  now?: () => number\n  /** The device's seal key for this credential: an x-only public key,\n   *  minted fresh for each credential, to which rekeys and epoch grants are\n   *  then sealed instead of the device key. See `seal.ts`. Omitted, the\n   *  credential is byte-identical to one minted before seal keys. */\n  seal?: string\n}", "  now?: () => number\n}", 1],
    ["  if (person && opts.expiresAt - now > PERSON_CREDENTIAL_MAX_SECONDS) throw new Error('a person credential may not run more than 30 days')\n  if (opts.seal !== undefined && !isSealPubkey(opts.seal)) throw new Error('a seal key must be an x-only public key on the curve')\n  const unsigned: UnsignedEvent = {", "  if (person && opts.expiresAt - now > PERSON_CREDENTIAL_MAX_SECONDS) throw new Error('a person credential may not run more than 30 days')\n  const unsigned: UnsignedEvent = {", 1],
    ["      ...(opts.label !== undefined ? [['label', opts.label]] : []),\n      ...(opts.seal !== undefined ? [[SEAL_TAG, opts.seal.toLowerCase()]] : []),\n    ],", "      ...(opts.label !== undefined ? [['label', opts.label]] : []),\n    ],", 1],
  ],
  "src/epoch.ts": [
    ["import { verifyEventUncached } from './verify.js'\nimport { newerCredential, openSealed, sealTo } from './seal.js'\nimport { withExpiration } from './expiration.js'", "import { verifyEventUncached } from './verify.js'\nimport { withExpiration } from './expiration.js'", 1],
    ["  /** Devices to seal the new secret for. Everybody still in the room,\n   *  except the removed participants' devices. A recipient given with its\n   *  newest credential is sealed to that credential's seal key, when it\n   *  names one; a bare device, to the device key (see `seal.ts`). The\n   *  `keys` map is keyed by device either way. */\n  recipients: ReadonlyArray<string | RekeyRecipient>\n  /** Participants removed at this step. Empty on a rekey that only turns", "  /** Devices to seal the new secret for. Everybody still in the room,\n   *  except the removed participants' devices. */\n  recipients: string[]\n  /** Participants removed at this step. Empty on a rekey that only turns", 1],
    ["\n/** A rekey recipient: a device, and the newest credential the sender holds\n *  for it. */\nexport interface RekeyRecipient {\n  device: string\n  credential?: DeviceCredential\n}\n\nfunction memberListOf(members: readonly string[], removed: readonly string[]): string[] {", "\nfunction memberListOf(members: readonly string[], removed: readonly string[]): string[] {", 1],
    ["  for (const raw of opts.closed ? [] : opts.recipients) {\n    const recipient = typeof raw === 'string' ? { device: raw } : raw\n    const device = requireHex32(recipient.device, 'recipient device')\n    keys[device] = sealTo(plaintext, opts.authoritySk, device, recipient.credential)\n  }", "  for (const raw of opts.closed ? [] : opts.recipients) {\n    const device = requireHex32(raw, 'recipient device')\n    keys[device] = nip44.v2.encrypt(plaintext, nip44.v2.utils.getConversationKey(opts.authoritySk, device))\n  }", 1],
    ["  deviceSk: Uint8Array\n  /** The seal key secrets this device holds, newest first, tried before\n   *  the device key (see `seal.ts`). */\n  sealSks?: readonly Uint8Array[]\n}", "  deviceSk: Uint8Array\n}", 1],
    ["    if (typeof mine === 'string') {\n      // A copy none of this device's keys opens is no copy: sealed to a\n      // seal key it has since erased, or one it never had. The rest of the\n      // rekey still says who was removed, so it is read without the secret,\n      // and the device asks for the epoch.\n      try {\n        const sealed = JSON.parse(openSealed(mine, event.pubkey, opts.deviceSk, opts.sealSks)) as Partial<SealedSecret>\n        if (sealed.v === 1 && typeof sealed.secret === 'string') {\n          const secret = base64urlnopad.decode(sealed.secret)\n          if (secret.length === 32) notice.secret = secret\n        }\n      } catch {\n        // No secret, as above.\n      }", "    if (typeof mine === 'string') {\n      const sealed = JSON.parse(\n        nip44.v2.decrypt(mine, nip44.v2.utils.getConversationKey(opts.deviceSk, event.pubkey)),\n      ) as Partial<SealedSecret>\n      if (sealed.v === 1 && typeof sealed.secret === 'string') {\n        const secret = base64urlnopad.decode(sealed.secret)\n        if (secret.length === 32) notice.secret = secret\n      }", 1],
    ["export function decodeEpochRequest(event: Event, opts: DecodeEpochRequestOptions): EpochRequest | null {\n  const read = readEpochRequest(event, opts)\n  return read && read.request\n}\n\n/** `decodeEpochRequest`, keeping the credential the request was made\n *  under: what the desk seals its answer by. */\nfunction readEpochRequest(event: Event, opts: DecodeEpochRequestOptions): { request: EpochRequest; credential: DeviceCredential } | null {\n  try {", "export function decodeEpochRequest(event: Event, opts: DecodeEpochRequestOptions): EpochRequest | null {\n  try {", 1],
    ["    }\n    return { request: { device: verdict.device, participant: verdict.participant, request: event.id }, credential: body.credential }\n  } catch {", "    }\n    return { device: verdict.device, participant: verdict.participant, request: event.id }\n  } catch {", 1],
    ["  refused?: EpochRefusal\n  /** The newest credential the authority holds for the device: the grant\n   *  is sealed to its seal key when it names one (see `seal.ts`). */\n  credential?: DeviceCredential\n  /** A conference room's end, in unix seconds: the event carries it as a", "  refused?: EpochRefusal\n  /** A conference room's end, in unix seconds: the event carries it as a", 1],
    ["      ], opts.expiresAt),\n      content: sealTo(JSON.stringify(body), opts.authoritySk, device, opts.credential),\n    },", "      ], opts.expiresAt),\n      content: nip44.v2.encrypt(JSON.stringify(body), nip44.v2.utils.getConversationKey(opts.authoritySk, device)),\n    },", 1],
    ["  deviceSk: Uint8Array\n  /** The seal key secrets this device holds: see\n   *  `DecodeRekeyOptions.sealSks`. */\n  sealSks?: readonly Uint8Array[]\n  request: string", "  deviceSk: Uint8Array\n  request: string", 1],
    ["    if (addressed === undefined || !hexEquals(addressed, device)) return null\n    const body = JSON.parse(openSealed(event.content, event.pubkey, opts.deviceSk, opts.sealSks)) as Partial<EpochGrantBody>\n    if (body.v !== 1 || typeof body.request !== 'string' || !hexEquals(body.request, opts.request)) return null", "    if (addressed === undefined || !hexEquals(addressed, device)) return null\n    const body = JSON.parse(\n      nip44.v2.decrypt(event.content, nip44.v2.utils.getConversationKey(opts.deviceSk, event.pubkey)),\n    ) as Partial<EpochGrantBody>\n    if (body.v !== 1 || typeof body.request !== 'string' || !hexEquals(body.request, opts.request)) return null", 1],
    ["  members?: () => readonly string[]\n  /**\n   * The newest credential the authority has seen for a device, from the\n   * roster. An answer is sealed to the newer of this and the one the\n   * request carries, so a thief replaying a device's older, still-live\n   * credential is answered under the seal key the device minted since.\n   * Keep it monotone: a roster entry carrying an older credential than one\n   * already seen must not replace it, or the thief can publish one.\n   */\n  credentialFor?: (device: string) => DeviceCredential | undefined\n  /** Somebody the room does not know asked, after a removal: what an app", "  members?: () => readonly string[]\n  /** Somebody the room does not know asked, after a removal: what an app", 1],
    ["  expiresAt?: number\n}\n\n/**\n * The credential to seal an answer to: the one the request carries, unless\n * the room has seen a newer one for the same device and participant that\n * still verifies. Shared by both desks.\n */\nexport function sealCredential(\n  request: { device: string; participant: string },\n  presented: DeviceCredential,\n  credentialFor: ((device: string) => DeviceCredential | undefined) | undefined,\n  roomId: string,\n  now: number,\n): DeviceCredential {\n  let known: DeviceCredential | undefined\n  try {\n    known = credentialFor?.(request.device)\n  } catch {\n    known = undefined\n  }\n  if (!known) return presented\n  const verdict = verifyDeviceCredential(known, { roomId, now })\n  if (!verdict.ok || verdict.device !== normaliseHex(request.device) || verdict.participant !== normaliseHex(request.participant)) return presented\n  return newerCredential(presented, known)\n}", "  expiresAt?: number\n}", 1],
    ["      if (closed) return\n      const read = readEpochRequest(event, {\n        roomId,", "      if (closed) return\n      const request = decodeEpochRequest(event, {\n        roomId,", 1],
    ["      })\n      if (!read || answered.has(read.request.request)) return\n      const request = read.request\n      let refused: EpochRefusal | undefined", "      })\n      if (!request || answered.has(request.request)) return\n      let refused: EpochRefusal | undefined", 1],
    ["        grant = refused\n          ? encodeEpochGrant({\n              roomId,\n              authoritySk: opts.authoritySk,\n              device: request.device,\n              request: request.request,\n              now: now(),\n              refused,\n              credential: sealCredential(request, read.credential, opts.credentialFor, roomId, now()),\n              expiresAt: opts.expiresAt,\n            })\n          : encodeEpochGrant({", "        grant = refused\n          ? encodeEpochGrant({ roomId, authoritySk: opts.authoritySk, device: request.device, request: request.request, now: now(), refused, expiresAt: opts.expiresAt })\n          : encodeEpochGrant({", 1],
    ["              ...(opts.members ? { members: [...opts.members()] } : {}),\n              credential: sealCredential(request, read.credential, opts.credentialFor, roomId, now()),\n              expiresAt: opts.expiresAt,", "              ...(opts.members ? { members: [...opts.members()] } : {}),\n              expiresAt: opts.expiresAt,", 1],
    ["  onUnknown?: () => void\n  /** The seal key secrets this device holds. Asked on every answer,\n   *  because a credential may renew while the ask is out. */\n  sealSks?: () => readonly Uint8Array[]\n}", "  onUnknown?: () => void\n}", 1],
    ["    unsub = opts.transport.subscribe([{ kinds: [KINDS.EPOCH_GRANT], '#d': [roomId], '#p': [device] }], (event) => {\n      const grant = decodeEpochGrant(event, {\n        roomId,\n        authority: opts.authority,\n        deviceSk: opts.deviceSk,\n        sealSks: opts.sealSks?.(),\n        request: request.id,\n        now: now(),\n      })\n      if (!grant) return", "    unsub = opts.transport.subscribe([{ kinds: [KINDS.EPOCH_GRANT], '#d': [roomId], '#p': [device] }], (event) => {\n      const grant = decodeEpochGrant(event, { roomId, authority: opts.authority, deviceSk: opts.deviceSk, request: request.id, now: now() })\n      if (!grant) return", 1],
  ],
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
  let kitText = readKit('src/credential.ts')
  const sourceText = readAtCommit('src/credential.ts')
  let missing = false
  for (const [kit, source, count] of SEAL_CHANGES['src/credential.ts']) {
    const found = kitText.split(kit).length - 1
    if (found !== count) {
      failures += 1
      missing = true
      console.error(`FAIL (declared change): src/credential.ts carries ${found} (not ${count}) of ${JSON.stringify(kit.trim().split('\n')[0].slice(0, 60))}... - update diff-source.mjs or restore it`)
      continue
    }
    kitText = kitText.split(kit).join(source)
  }
  let stripped = kitText
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

/**
 * The known-members gate (#207, unreleased): a rekey and an authority grant
 * may carry the room's member list, the desk takes `known`, `members` and
 * `onUnknown`, refuses an unknown participant with `unknown` once anybody
 * has been removed, and the requester waits on `unknown` instead of giving
 * up. With no removal and no member list every event is byte-identical to
 * 0.5.1's. Declared as new text -> 0.5.1 text, generated hunk by hunk from
 * the diff with one line of context, and applied before everything else.
 */
const KNOWN_MEMBERS_CHANGES = {
  "src/epoch.ts": [
    ["\n/** A participant list as a body carries it: lower-case, deduplicated and\n *  sorted, or undefined when the field is absent or is not a list of keys.\n *  Undefined is the safe reading, since it makes nobody known. */\nexport function readMemberList(raw: unknown): string[] | undefined {\n  if (!Array.isArray(raw) || !raw.every((p) => typeof p === 'string' && HEX64.test(p))) return undefined\n  return [...new Set((raw as string[]).map(normaliseHex))].sort()\n}\n\nfunction requireHex32(value: string, what: string): string {", "\nfunction requireHex32(value: string, what: string): string {", 1],
    ["  commit?: string\n  /** The participants the authority knows to be in the room as it rekeys,\n   *  removed ones excepted. A member desk hands an epoch on only to\n   *  participants it knows once anyone has been removed (#207). Absent\n   *  from a rekey written without it. */\n  members?: string[]\n  /** Device pubkey to a NIP-44 envelope, from the authority to that device,", "  commit?: string\n  /** Device pubkey to a NIP-44 envelope, from the authority to that device,", 1],
    ["  commit?: boolean\n  /** Every participant the authority knows to be in the room, not only the\n   *  ones present now: a member who is offline as the room rekeys is still\n   *  a member. Removed participants are dropped. Omitted, the event is\n   *  byte-identical to before. */\n  members?: string[]\n  now: number", "  commit?: boolean\n  now: number", 1],
    ["  expiresAt?: number\n}\n\nfunction memberListOf(members: readonly string[], removed: readonly string[]): string[] {\n  const out = new Set(members.map((p) => requireHex32(p, 'member participant')))\n  for (const p of removed) out.delete(normaliseHex(p))\n  return [...out].sort()\n}", "  expiresAt?: number\n}", 1],
    ["    ...(opts.commit ? { commit: epochCommitment(roomId, epoch, opts.next.secret) } : {}),\n    ...(opts.members !== undefined ? { members: memberListOf(opts.members, removed) } : {}),\n    keys,", "    ...(opts.commit ? { commit: epochCommitment(roomId, epoch, opts.next.secret) } : {}),\n    keys,", 1],
    ["  secret?: Uint8Array\n  /** The participants the authority listed as in the room. Absent from a\n   *  rekey written without the list. */\n  members?: string[]\n  /** True for a current-state grant, whose removed list is cumulative.", "  secret?: Uint8Array\n  /** True for a current-state grant, whose removed list is cumulative.", 1],
    ["    if (typeof body.by === 'string' && HEX64.test(body.by)) notice.by = normaliseHex(body.by)\n    const members = readMemberList(body.members)\n    if (members) notice.members = members\n    const device = getPublicKey(opts.deviceSk)", "    if (typeof body.by === 'string' && HEX64.test(body.by)) notice.by = normaliseHex(body.by)\n    const device = getPublicKey(opts.deviceSk)", 1],
    ["\n/** How often a desk reports the same unknown participant while they keep\n *  asking: often enough that a missed \"let them in?\" comes back, rarely\n *  enough that it is not a nag. */\nexport const REPORT_UNKNOWN_EVERY_SECONDS = 60\n\n/** Why the authority would not hand an epoch over. `unknown` is not final:\n *  the room has removed somebody, and does not yet know this participant,\n *  so it waits for a member to let them in (#207). */\nexport type EpochRefusal = 'removed' | 'closed' | 'unknown'\n", "\n/** Why the authority would not hand an epoch over. */\nexport type EpochRefusal = 'removed' | 'closed'\n", 1],
    ["  removed?: string[]\n  members?: string[]\n  refused?: EpochRefusal", "  removed?: string[]\n  refused?: EpochRefusal", 1],
    ["  removed?: string[]\n  /** The participants the authority knows, so the requester's own member\n   *  desk knows them too. Omitted, the body is as before. */\n  members?: string[]\n  refused?: EpochRefusal", "  removed?: string[]\n  refused?: EpochRefusal", 1],
    ["    body.removed = [...new Set((opts.removed ?? []).map((p) => requireHex32(p, 'removed participant')))].sort()\n    if (opts.members !== undefined) body.members = memberListOf(opts.members, body.removed)\n  }", "    body.removed = [...new Set((opts.removed ?? []).map((p) => requireHex32(p, 'removed participant')))].sort()\n  }", 1],
    ["      passed?: RoomEpoch[]\n      /** The participants the room knows, when the answer carried them. */\n      members?: string[]\n      refused?: undefined", "      passed?: RoomEpoch[]\n      refused?: undefined", 1],
    ["    if (body.v !== 1 || typeof body.request !== 'string' || !hexEquals(body.request, opts.request)) return null\n    if (body.refused === 'removed' || body.refused === 'closed' || body.refused === 'unknown') return { refused: body.refused }\n    if (!Number.isSafeInteger(body.epoch) || (body.epoch as number) < 0 || (body.epoch as number) > MAX_EPOCH) return null", "    if (body.v !== 1 || typeof body.request !== 'string' || !hexEquals(body.request, opts.request)) return null\n    if (body.refused === 'removed' || body.refused === 'closed') return { refused: body.refused }\n    if (!Number.isSafeInteger(body.epoch) || (body.epoch as number) < 0 || (body.epoch as number) > MAX_EPOCH) return null", 1],
    ["      : []\n    const members = readMemberList(body.members)\n    const listed = members ? { members } : {}\n    if (body.epoch === 0) return { epoch: { epoch: 0 }, removed, ...listed }\n    if (typeof body.secret !== 'string') return null", "      : []\n    if (body.epoch === 0) return { epoch: { epoch: 0 }, removed }\n    if (typeof body.secret !== 'string') return null", 1],
    ["    if (secret.length !== 32) return null\n    return { epoch: { epoch: body.epoch as number, secret }, removed, ...listed }\n  } catch {", "    if (secret.length !== 32) return null\n    return { epoch: { epoch: body.epoch as number, secret }, removed }\n  } catch {", 1],
    ["  closed?: () => boolean\n  /**\n   * Whether the room knows this participant: on the authority's member\n   * list, in the room now, or let in. Consulted only once somebody has been\n   * removed, and then everybody else is answered `unknown` (#207). Without\n   * it, after a removal, nobody is known. Asked on every request.\n   */\n  known?: (participant: string) => boolean\n  /** The participants to tell a granted device about, so its own member\n   *  desk knows them too. Asked on every grant. */\n  members?: () => readonly string[]\n  /** Somebody the room does not know asked, after a removal: what an app\n   *  turns into \"let them in?\". Called once per participant, and again\n   *  every `reportUnknownEvery` seconds while they keep asking. Letting them in\n   *  is making `known` say yes; the requester's next ask is then granted. */\n  onUnknown?: (request: EpochRequest) => void\n  /** Seconds before a participant still unknown and still asking is\n   *  reported again. Default 60. */\n  reportUnknownEvery?: number\n  policy?: RoomPolicy", "  closed?: () => boolean\n  policy?: RoomPolicy", 1],
    [" * all: a stranger learns nothing, not even that a desk is here.\n *\n * The admission proof is made under the epoch-0 room key, which a removed\n * member still holds, so removal by participant alone is undone by a fresh\n * key (#207). Once anyone has been removed the desk therefore grants only\n * to participants the room knows (`known`), and answers anybody else\n * `unknown` until a member lets them in. A room that has never removed\n * anybody is answered exactly as before.\n */", " * all: a stranger learns nothing, not even that a desk is here.\n */", 1],
    ["  const answered = new Set<string>()\n  /** Requests answered `unknown`, which the requester sends again while it\n   *  waits: answered again only once they are known. */\n  const waiting = new Set<string>()\n  /** When each unknown participant was last reported through `onUnknown`,\n   *  so one still waiting is reported again only after `reportUnknownEvery`. */\n  const reported = new Map<string, number>()\n  const bound = (set: Set<string>): void => {\n    if (set.size > 256) set.delete(set.values().next().value!)\n  }\n  let closed = false", "  const answered = new Set<string>()\n  let closed = false", 1],
    ["      if (!request || answered.has(request.request)) return\n      let refused: EpochRefusal | undefined", "      if (!request || answered.has(request.request)) return\n      answered.add(request.request)\n      if (answered.size > 256) answered.delete(answered.values().next().value!)\n      let refused: EpochRefusal | undefined", 1],
    ["      else if (opts.removed().has(request.participant)) refused = 'removed'\n      else if (opts.removed().size > 0 && !opts.known?.(request.participant)) refused = 'unknown'\n      if (refused === 'unknown') {\n        if (waiting.has(request.request)) return\n        waiting.add(request.request)\n        bound(waiting)\n      } else {\n        waiting.delete(request.request)\n        answered.add(request.request)\n        bound(answered)\n      }\n      let grant: Event", "      else if (opts.removed().has(request.participant)) refused = 'removed'\n      let grant: Event", 1],
    ["              removed: [...opts.removed()],\n              ...(opts.members ? { members: [...opts.members()] } : {}),\n              expiresAt: opts.expiresAt,", "              removed: [...opts.removed()],\n              expiresAt: opts.expiresAt,", 1],
    ["      opts.transport.publish(grant).catch(() => {})\n      if (refused === 'unknown' && now() - (reported.get(request.participant) ?? -Infinity) >= (opts.reportUnknownEvery ?? REPORT_UNKNOWN_EVERY_SECONDS)) {\n        reported.set(request.participant, now())\n        if (reported.size > 256) reported.delete(reported.keys().next().value!)\n        opts.onUnknown?.(request)\n      }\n      if (!refused) reported.delete(request.participant)\n      if (refused) opts.onRefused?.(request, refused)", "      opts.transport.publish(grant).catch(() => {})\n      if (refused) opts.onRefused?.(request, refused)", 1],
    ["  members?: MemberEpochSource\n  /** The authority said the room does not know this participant yet. Not\n   *  final: the ask goes on, and a member letting them in settles it. */\n  onUnknown?: () => void\n}", "  members?: MemberEpochSource\n}", 1],
    ["  constructor(refused: EpochRefusal) {\n    super(\n      refused === 'removed'\n        ? 'you were removed from this room'\n        : refused === 'unknown'\n          ? 'nobody in this room has let you in yet'\n          : 'this room has been closed',\n    )\n    this.name = 'EpochRefusedError'", "  constructor(refused: EpochRefusal) {\n    super(refused === 'removed' ? 'you were removed from this room' : 'this room has been closed')\n    this.name = 'EpochRefusedError'", 1],
    [" *  with `EpochRefusedError` on a refusal, and with a plain error when\n *  nobody answers inside the timeout. `unknown` is not final: the ask goes\n *  on, and only a timeout after it rejects, with `EpochRefusedError`. */\nexport function requestRoomEpoch(opts: RequestRoomEpochOptions): Promise<Exclude<EpochGrant, { refused: EpochRefusal }>> {", " *  with `EpochRefusedError` on a refusal, and with a plain error when\n *  nobody answers inside the timeout. */\nexport function requestRoomEpoch(opts: RequestRoomEpochOptions): Promise<Exclude<EpochGrant, { refused: EpochRefusal }>> {", 1],
    ["    let stopMembers = () => {}\n    let unknown = false\n    const finish = (settle: () => void): void => {", "    let stopMembers = () => {}\n    const finish = (settle: () => void): void => {", 1],
    ["      if (!grant) return\n      if (grant.refused === 'unknown') {\n        if (!unknown) opts.onUnknown?.()\n        unknown = true\n      } else if (grant.refused) finish(() => reject(new EpochRefusedError(grant.refused)))\n      else finish(() => resolve(grant))", "      if (!grant) return\n      if (grant.refused) finish(() => reject(new EpochRefusedError(grant.refused)))\n      else finish(() => resolve(grant))", 1],
    ["    expiry = setTimeout(\n      () =>\n        finish(() =>\n          reject(unknown ? new EpochRefusedError('unknown') : new Error('the room has moved to a newer epoch and its keeper is not answering')),\n        ),\n      opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,", "    expiry = setTimeout(\n      () => finish(() => reject(new Error('the room has moved to a newer epoch and its keeper is not answering'))),\n      opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,", 1]
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
  checkWholeFileWithDeclaredChanges(`src/${f}`, [...(GRANT_PUBLICATION_CHANGES[`src/${f}`] ?? []), ...(DESTRUCT_CHANGES[`src/${f}`] ?? []), ...(SCHEDULE_CHANGES[`src/${f}`] ?? []), ...(SEAL_CHANGES[`src/${f}`] ?? []), ...(KNOWN_MEMBERS_CHANGES[`src/${f}`] ?? []), ...(MEMBER_EPOCH_CHANGES[`src/${f}`] ?? []), ...(ROOM_RELAY_CHANGES[`src/${f}`] ?? []), ...CONFERENCE_CHANGES[`src/${f}`]], [["from './transport.js'", "from './relay-pool.js'"]])
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
