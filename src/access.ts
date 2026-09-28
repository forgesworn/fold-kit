import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils'
import { getPublicKey } from 'nostr-tools/pure'
import { hexEquals, normaliseHex } from './hex.js'
import type { KindredProof, RoomPolicy } from './types.js'

/** Closest first, matching the canonical order in the kindred primitive. */
const TIER_RANK: Record<string, number | undefined> = { kin: 3, kith: 2, ken: 1, open: 0 }

/**
 * The exact bytes a kindred proof signs over. Every field that changes the
 * proof's meaning is in here, so tampering with any one of them - tier,
 * subject, room, nonce or expiry - invalidates the signature.
 *
 * `room` and `nonce` are covered deliberately: see `KindredProof`. A proof
 * signed by an implementation that omits them reconstructs a different message
 * and fails the signature check, which is the right way round - an older proof
 * is refused rather than silently admitted somewhere it was never meant to go.
 */
function canonicalMessage(
  tier: KindredProof['tier'],
  participant: string,
  room: string,
  nonce: string,
  expiresAt: number,
): Uint8Array {
  return sha256(
    new TextEncoder().encode(`kithmoot/v1/kindred:${tier}:${participant}:${room}:${nonce}:${expiresAt}`),
  )
}

export interface IssueKindredProofOptions {
  /** The issuer's secret key. */
  hostSk: Uint8Array
  participant: string
  tier: KindredProof['tier']
  /** The room this proof admits the participant to. */
  roomId: string
  /** Unix seconds. */
  expiresAt: number
  /** 32 bytes, hex. Supply one only to make a proof reproducible - the
   *  interop vectors do; everything else wants the random default. */
  nonce?: string
}

/** Vouch for a participant at a tier, in one room, until an expiry. */
export function issueKindredProof(opts: IssueKindredProofOptions): KindredProof {
  // `participant` and `roomId` are identifiers handed in by the caller -
  // possibly typed or pasted - so they are canonicalised here, at the point
  // they enter the proof, rather than left for `evaluateAccess`'s equality
  // checks to paper over.
  const participant = normaliseHex(opts.participant)
  const room = normaliseHex(opts.roomId)
  const nonce = normaliseHex(opts.nonce ?? bytesToHex(randomBytes(32)))
  const sig = schnorr.sign(canonicalMessage(opts.tier, participant, room, nonce, opts.expiresAt), opts.hostSk)
  return {
    tier: opts.tier,
    participant,
    issuer: getPublicKey(opts.hostSk),
    room,
    nonce,
    sig: bytesToHex(sig),
    expiresAt: opts.expiresAt,
  }
}

/**
 * Decide whether `participant` may join a room under `policy`.
 *
 * `ken` is one-way recognition - pinning someone's key from an authoritative
 * source, with no bond back - so it never satisfies a `kith` gate. `kin` is
 * closer than `kith` and does. Checks run cheapest first and never throw:
 * participant match, room match, expiry, issuer trust, tier, then the schnorr
 * verification last, since it is the most expensive.
 */
export function evaluateAccess(
  policy: RoomPolicy,
  participant: string,
  proof: KindredProof | undefined,
  now: number,
  roomId: string,
): { admitted: boolean; reason: string } {
  // A members list closes the door before any tier is considered: a
  // direct message is open in tier and shut to everybody but its two.
  if (policy.members !== undefined && !policy.members.some((m) => hexEquals(m, participant))) {
    return { admitted: false, reason: 'not a member' }
  }
  if (policy.tier === 'open') return { admitted: true, reason: 'open room' }
  if (!proof) return { admitted: false, reason: 'no kindred proof' }
  // Hex, compared case-insensitively throughout this function: see
  // `hexEquals` and `vectors/README.md`. An allow-list entry, or a proof,
  // stored in upper-case hex names exactly the same identifier and must not
  // be rejected on case alone.
  if (!hexEquals(proof.participant, participant)) return { admitted: false, reason: 'proof names another participant' }
  // A proof is a grant in one room, not a bearer token - see `KindredProof`.
  if (proof.room === undefined || !hexEquals(proof.room, roomId)) {
    return { admitted: false, reason: 'proof names another room' }
  }
  if (proof.expiresAt <= now) return { admitted: false, reason: 'expired' }
  if (!policy.admitted?.some((a) => hexEquals(a, proof.issuer))) {
    return { admitted: false, reason: 'untrusted issuer' }
  }

  // Fail closed on a tier we do not recognise. TIER_RANK[unknown] is
  // undefined and `undefined < 2` is false, so the obvious comparison skips
  // the rejection branch and admits - the opposite of what a gate is for. A
  // trusted issuer's typo, or a looser independent implementation, is all it
  // would take.
  const rank = TIER_RANK[proof.tier]
  if (rank === undefined) return { admitted: false, reason: 'unrecognised tier' }
  if (rank < (TIER_RANK[policy.tier] ?? 0)) return { admitted: false, reason: 'tier too low' }

  try {
    const message = canonicalMessage(proof.tier, proof.participant, proof.room, proof.nonce, proof.expiresAt)
    if (!schnorr.verify(hexToBytes(proof.sig), message, hexToBytes(proof.issuer))) {
      return { admitted: false, reason: 'bad signature' }
    }
  } catch {
    return { admitted: false, reason: 'bad signature' }
  }

  return { admitted: true, reason: 'kindred proof accepted' }
}

/** Every wire-format literal this module owns (each one a kithmoot protocol string), frozen for
 *  `src/labels.test.ts`, which checks each module against its own exported
 *  list rather than scanning file text for matching comments. Pure data -
 *  adding this export changes no runtime behaviour. */
export const ACCESS_LABELS = [
  "kithmoot/v1/kindred:",
] as const
