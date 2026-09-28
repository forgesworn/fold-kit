#!/usr/bin/env node
// Proves every moved module's body is byte-identical to the pinned KithMoot
// source commit, as docs/plans/2026-09-28-circle-kit-extraction.md §3.3
// step 2 (girnel repository) requires: "a script that diffs every moved
// file against the pinned kithmoot commit with import lines stripped: zero
// diff."
//
// Needs a local checkout of the pinned source commit (see EXTRACTION.md for
// the exact commit). Point FOLD_KIT_SOURCE_DIR at that checkout's root:
//
//   FOLD_KIT_SOURCE_DIR=/path/to/kithmoot npm run diff-source
//
// This script only reads from that checkout - it never writes to it. With
// no FOLD_KIT_SOURCE_DIR set (the default in CI, which has no access to the
// private source repository), it prints a notice and exits 0 rather than
// failing the build: the comparison is a local development gate, run by
// hand before every commit that touches a moved module, not a CI check.
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
 * Chunk comparison for modules that were subsetted or had a function/const
 * extracted into a new file (kinds.ts, types.ts, access.ts, channel.ts - see
 * docs/plans/2026-09-28-circle-kit-extraction.md §1.1). Each chunk is an
 * exact, verbatim multi-line excerpt (doc comment plus declaration) that
 * must appear byte-identical in both the kit file and the pinned source
 * file.
 */
function checkChunks(kitPath, sourcePath, chunks) {
  const kitText = readKit(kitPath)
  const sourceText = readAtCommit(sourcePath)
  for (const chunk of chunks) {
    const inKit = kitText.includes(chunk)
    const inSource = sourceText.includes(chunk)
    if (!inKit || !inSource) {
      failures += 1
      const label = chunk.split('\n')[0].slice(0, 60)
      console.error(`FAIL (chunk): "${label}..." ${inKit ? '' : 'missing from kit file '}${inSource ? '' : 'missing from pinned source '}(${kitPath} <-> ${sourcePath}@${sourceCommit})`)
    }
  }
  console.log(`ok   (${chunks.length} chunks): ${kitPath} <-> ${sourcePath}@${sourceCommit}`)
}

function printFirstDiffLine(a, b, label) {
  const aLines = a.split('\n')
  const bLines = b.split('\n')
  for (let i = 0; i < Math.max(aLines.length, bLines.length); i++) {
    if (aLines[i] !== bLines[i]) {
      console.error(`  first differing line ${i + 1} in ${label}:`)
      console.error(`    kit:    ${aLines[i] ?? '<EOF>'}`)
      console.error(`    source: ${bLines[i] ?? '<EOF>'}`)
      break
    }
  }
}

// --- Whole-file modules (import paths unchanged, or rewritten as noted) ---

for (const f of ['hex.ts', 'verify.ts', 'identity.ts', 'credential.ts', 'room.ts', 'network-hints.ts', 'display-name.ts', 'link.ts', 'lane.ts']) {
  checkWholeFile(`src/${f}`, `src/${f}`)
}
for (const f of ['invitation.ts', 'persistent-invitation.ts', 'epoch.ts']) {
  checkWholeFile(`src/${f}`, `src/${f}`, [["from './transport.js'", "from './relay-pool.js'"]])
}
checkWholeFile('test/sim-relay.ts', 'test/sim-relay.ts', [["from '../src/transport.js'", "from '../src/relay-pool.js'"]])

// --- Subsetted / extracted modules: verbatim chunk comparison ---

checkChunks('src/kinds.ts', 'src/kinds.ts', [
  "  /** Device credential. Signed by the participant key; never published to a\n   *  relay - it travels inside the encrypted roster, so relays never see the\n   *  participant pubkey. */\n  CREDENTIAL: 20460,",
  "  /** Chat message, encrypted to the room key and published once, exactly\n   *  like the roster. Unlike the roster this is a DURABLE kind (regular\n   *  event range, not ephemeral) - chat history is the point, so it must\n   *  survive a relay restart and be there for late joiners. */\n  CHAT: 1460,",
  "  /** A prospective member proving possession of a room invitation.\n   *\n   * Ephemeral deliberately: it is a live rendezvous with an inviter, not a\n   * request a relay should retain. The public `d` tag is derived from the\n   * bearer capability; the request body is encrypted under a separate key\n   * derived from that capability. */\n  INVITATION_REQUEST: 20466,",
  "  /** A delegated responder's encrypted response carrying the room traffic\n   * secret and its root-authenticated, room-bound delegation chain. Addressed\n   * to the requester's one-use pubkey; knowing the bearer does not let\n   * somebody nominate a responder or substitute a room. Ephemeral for the\n   * same reason as the request. */\n  INVITATION_GRANT: 20467,",
  "  /** A durable, creator-authenticated tombstone for one invitation.\n   *\n   * Unlike the live request/grant exchange this MUST be a regular stored\n   * event: a delegated responder that was offline when the creator rotated\n   * the link has to learn that fact before it starts answering the old link\n   * again. The invitation id is unique, so one valid retirement is final. */\n  INVITATION_RETIREMENT: 1461,",
  "  /** A persistent group's invitation, signed by the pinned inviter and\n   * encrypted under a separate bearer-derived key. Regular stored event:\n   * newcomers can enter with every member offline. Contains epoch 0 only;\n   * it never grants authority to rekey or bypass a later removal. */\n  GROUP_INVITATION: 1463,",
  "  /** A room moving to a new epoch: a fresh traffic secret, sealed per\n   * remaining device, with the participants removed at this step named.\n   *\n   * Durable, and addressed by the public room id, so a client can find the\n   * room's current epoch from the id alone and know it is behind before it\n   * says anything under a key that is dead. The body is encrypted to the\n   * previous epoch's key, so a relay sees the room id, the epoch number,\n   * the authority's pubkey and a size, and nothing about who was kept or\n   * removed. Signed only by the room's authority, the root inviter pinned\n   * in the link. See `epoch.ts`. */\n  ROOM_REKEY: 1462,",
  "  /** A member that missed a rekey - it was offline, or it is arriving now -\n   * asking the authority for the current epoch, proving which participant it\n   * speaks for with its device credential. Encrypted to the authority and\n   * ephemeral: it is a live handshake, not a record. */\n  EPOCH_REQUEST: 20468,",
  "  /** The authority's answer, sealed to the asking device: the current epoch's\n   * secret and the removed set, or a refusal. Ephemeral for the same reason. */\n  EPOCH_GRANT: 20469,",
])

checkChunks('src/types.ts', 'src/types.ts', [
  "/** A device credential is an ordinary signed Nostr event, never published bare. */\nexport type DeviceCredential = Event",
  "/** Kindred tiers, closest first: family, mutual verified bond, one-way\n *  recognition, no requirement at all. */\nexport type AccessTier = 'open' | 'ken' | 'kith' | 'kin'",
  "/** What a room requires of its agents. `owned-by-members`: an agent is\n *  admitted to the roster only with a verified ownership proof from a\n *  participant who is in the room. See `AgentOwnership`. */\nexport type AgentRule = 'owned-by-members'",
  "export interface RoomPolicy {\n  tier: AccessTier\n  admitted?: string[]\n  agents?: AgentRule\n  /** When present, the only participants admitted, whatever the tier\n   *  says. A direct message is a room whose policy lists two. See\n   *  `docs/messages.md`. */\n  members?: string[]\n  /** A quiet room: its chat rides the kind 1059 firehose as dead drops to\n   *  keys derived from the epoch key, on a cadence, so a relay cannot tell\n   *  whether anything was said, by whom, or when. Only with `members`,\n   *  because everybody derives every member's keys. Rides here so that\n   *  everyone who joins agrees on how the room talks, exactly as they\n   *  agree on who may enter. See `quiet.ts`. */\n  quiet?: true\n}",
  "export type KindredProof = {\n  tier: Exclude<AccessTier, 'open'>\n  participant: string\n  issuer: string\n  /** The room id this proof is valid in. */\n  room: string\n  /** 32 random bytes, hex, unique to this proof. Signed over, so two proofs\n   *  on identical terms are still distinguishable - which is what a revocation\n   *  list, or an audit, needs to name one of them. */\n  nonce: string\n  sig: string\n  expiresAt: number\n}",
])

checkChunks('src/access.ts', 'src/access.ts', [
  "function canonicalMessage(\n  tier: KindredProof['tier'],\n  participant: string,\n  room: string,\n  nonce: string,\n  expiresAt: number,\n): Uint8Array {\n  return sha256(\n    new TextEncoder().encode(`kithmoot/v1/kindred:${tier}:${participant}:${room}:${nonce}:${expiresAt}`),\n  )\n}",
  "export interface IssueKindredProofOptions {",
  "export function issueKindredProof(opts: IssueKindredProofOptions): KindredProof {",
  "export function evaluateAccess(\n  policy: RoomPolicy,\n  participant: string,\n  proof: KindredProof | undefined,\n  now: number,\n  roomId: string,\n): { admitted: boolean; reason: string } {",
  'export const ACCESS_LABELS = [\n  "kithmoot/v1/kindred:",\n] as const',
])

checkChunks('src/channel.ts', 'src/chat.ts', [
  "export const CHANNEL_ID_INFO = 'kithmoot/v1/channel-id/'",
  "export const CHANNEL_KEY_INFO = 'kithmoot/v1/channel-key/'",
  "export function deriveChannel(roomId: string, roomKey: Uint8Array, channel?: string): { id: string; key: Uint8Array } {\n  if (channel === undefined) return { id: roomId, key: roomKey }\n  if (channel.length === 0 || channel.length > MAX_CHANNEL_NAME_LENGTH) throw new Error('channel name out of range')\n  const idBytes = hkdf(sha256, roomKey, undefined, CHANNEL_ID_INFO + channel, 32)\n  const key = hkdf(sha256, roomKey, undefined, CHANNEL_KEY_INFO + channel, 32)\n  const id = Array.from(idBytes, (b) => b.toString(16).padStart(2, '0')).join('')\n  return { id, key }\n}",
])

if (failures > 0) {
  console.error(`\ndiff-source: ${failures} difference(s) found against ${sourceCommit}`)
  process.exit(1)
}
console.log(`\ndiff-source: zero differences against ${sourceCommit}`)
