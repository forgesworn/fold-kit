import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { randomBytes } from '@noble/hashes/utils'
import { base64urlnopad } from '@scure/base'
import { normaliseHex } from './hex.js'
import type { AccessTier, RoomPolicy } from './types.js'
import { MAX_RELAY_HINTS, safeRelayUrls } from './network-hints.js'

const ROOM_ID_INFO = 'kithmoot/v1/room-id'
const ROOM_KEY_INFO = 'kithmoot/v1/room-key'

const utf8Encoder = new TextEncoder()
const utf8Decoder = new TextDecoder()

/** Generate a fresh 32-byte room traffic secret.
 *
 * Legacy v1 links carry this directly. New app links exchange it through
 * `invitation.ts` and never expose it in the URL. */
export function generateRoomSecret(): Uint8Array {
  return randomBytes(32)
}

/**
 * Derive the public room identifier and the symmetric room key from the secret.
 *
 * The two are derived with separate HKDF info strings so that publishing the
 * room id (which relays necessarily see) reveals nothing about the room key.
 */
export function deriveRoom(secret: Uint8Array): { roomId: string; roomKey: Uint8Array } {
  if (secret.length !== 32) throw new Error('room secret must be 32 bytes')
  const idBytes = hkdf(sha256, secret, undefined, ROOM_ID_INFO, 32)
  const roomKey = hkdf(sha256, secret, undefined, ROOM_KEY_INFO, 32)
  const roomId = Array.from(idBytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return { roomId, roomKey }
}

interface JoinPayload {
  s: string
  r: string[]
  /** The room's access policy. */
  a?: RoomPolicy
}

const TIERS: AccessTier[] = ['open', 'ken', 'kith', 'kin']
const AGENT_RULES = ['owned-by-members']
const MAX_POLICY_KEYS = 256

/**
 * Parse an access policy out of a URL fragment, which is untrusted input.
 *
 * A policy that does not parse is refused rather than silently dropped: a
 * dropped policy is an open room, and failing open is exactly the mistake
 * carrying the policy in the capability is meant to prevent.
 */
export function parseRoomPolicy(raw: unknown): RoomPolicy | undefined {
  if (raw === undefined || raw === null) return undefined
  if (typeof raw !== 'object') throw new Error('join URL carries a malformed access policy')
  const policy = raw as RoomPolicy
  if (!TIERS.includes(policy.tier)) throw new Error('join URL carries an access policy at an unknown tier')
  if (policy.admitted !== undefined) {
    if (!Array.isArray(policy.admitted) || policy.admitted.length > MAX_POLICY_KEYS ||
        !policy.admitted.every((a) => typeof a === 'string' && /^[0-9a-fA-F]{64}$/.test(a))) {
      throw new Error('join URL carries a malformed access policy')
    }
  }
  // A members list is a closed door, so a malformed one is refused rather
  // than dropped: dropping it would open the room to anybody with the link.
  if (policy.members !== undefined) {
    if (!Array.isArray(policy.members) || policy.members.length === 0 || policy.members.length > MAX_POLICY_KEYS ||
        !policy.members.every((m) => typeof m === 'string' && /^[0-9a-fA-F]{64}$/.test(m))) {
      throw new Error('join URL carries a malformed members list')
    }
  }
  // An agent rule this reader does not know is refused for the same reason
  // an unknown tier is: dropping it would admit what the room meant to keep
  // out.
  if (policy.agents !== undefined && !AGENT_RULES.includes(policy.agents)) {
    throw new Error('join URL carries an access policy with an unknown agent rule')
  }
  // A quiet room without a members list has nobody to derive keys for, and
  // a quiet flag in any shape but `true` is a reader that would talk in the
  // open while the rest of the room talks in drops. Both refused.
  if (policy.quiet !== undefined && (policy.quiet !== true || policy.members === undefined)) {
    throw new Error('join URL asks for a quiet room without a members list')
  }
  // The allow-list is exactly the case this rule was written for: entries a
  // person typed or pasted into a link. Canonicalise here, at the point they
  // enter the system off the URL, rather than relying on every reader to
  // compare them case-insensitively.
  const parsed: RoomPolicy = policy.admitted
    ? { tier: policy.tier, admitted: policy.admitted.map(normaliseHex) }
    : { tier: policy.tier }
  if (policy.agents !== undefined) parsed.agents = policy.agents
  if (policy.members !== undefined) parsed.members = [...new Set(policy.members.map(normaliseHex))]
  if (policy.quiet === true) parsed.quiet = true
  return parsed
}

/**
 * Build a legacy v1 join URL. The secret and relay hints live in the fragment, which
 * browsers never transmit to the server - the host of kithmoot.com learns
 * nothing about which room you are joining.
 *
 * Encoding uses @scure/base and TextEncoder/TextDecoder rather than a
 * Node-only global: this library ships to a browser PWA as well as to Node,
 * and Node-only globals do not exist there.
 *
 * The access policy rides here too. It is deliberately NOT a room descriptor
 * event on a relay: the URL is the capability, so everyone who joins holds
 * the same policy bytes and agreement is structural, with nothing to fetch
 * before a member can check another member's tier and no durable artefact of
 * the room on any relay. The cost is that the policy cannot change mid-room -
 * a new rule is a new link. See `docs/decisions.md`.
 */
export function encodeJoinUrl(
  base: string,
  secret: Uint8Array,
  relays: string[],
  policy?: RoomPolicy,
): string {
  if (secret.length !== 32) throw new Error('room secret must be 32 bytes')
  const payload: JoinPayload = { s: base64urlnopad.encode(secret), r: relays }
  if (policy) payload.a = policy
  const encoded = base64urlnopad.encode(utf8Encoder.encode(JSON.stringify(payload)))
  return `${base}#${encoded}`
}

/** Decode a legacy v1 room-secret link. Version 2 invitation links are
 * resolved by `invitation.ts` plus the app's URL envelope. */
export function decodeJoinUrl(url: string): {
  secret: Uint8Array
  relays: string[]
  policy?: RoomPolicy
} {
  const hash = new URL(url).hash.slice(1)
  if (!hash) throw new Error('join URL has no fragment')
  if (hash.length > 16_384) throw new Error('join URL fragment is too large')
  let payload: JoinPayload
  try {
    payload = JSON.parse(utf8Decoder.decode(base64urlnopad.decode(hash))) as JoinPayload
  } catch {
    throw new Error('join URL fragment is not valid')
  }

  let secret: Uint8Array
  try {
    secret = base64urlnopad.decode(payload.s)
  } catch {
    throw new Error('join URL carries a malformed secret')
  }
  if (secret.length !== 32) throw new Error('join URL carries a malformed secret')
  if (Array.isArray(payload.r) && payload.r.length > MAX_RELAY_HINTS) throw new Error('join URL carries too many relay hints')

  const policy = parseRoomPolicy(payload.a)
  const relays = safeRelayUrls(payload.r)
  return policy ? { secret, relays, policy } : { secret, relays }
}

/** Every wire-format literal this module owns (each one a kithmoot protocol string), frozen for
 *  `src/labels.test.ts`, which checks each module against its own exported
 *  list rather than scanning file text for matching comments. Pure data -
 *  adding this export changes no runtime behaviour. */
export const ROOM_LABELS = [
  "kithmoot/v1/room-id",
  "kithmoot/v1/room-key",
] as const
