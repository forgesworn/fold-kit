import { normalizeURL } from 'nostr-tools/utils'
import { isSafeRelayUrl, MAX_RELAY_HINTS } from './network-hints.js'

/**
 * A room's own relays, carried in its signed group invitation (kind 1463).
 *
 * The relays a room is created on are its meeting place: every member's pool
 * includes them, whatever else that member uses, so two members can never
 * end up on disjoint relays. A link's relay hints are unsigned and drift as
 * links are re-shared; the invitation's list is signed by the inviter, so a
 * stale bookmark converges on it.
 *
 * The list is strict: one to `MAX_INVITATION_RELAYS` distinct URLs, each a
 * safe relay URL already in canonical form (`normalizeURL` from
 * `nostr-tools/utils`: lower-case host, no default port, no trailing slash
 * except the root's, sorted query), with no credentials. Anything else
 * refuses the whole envelope; a list is never silently trimmed.
 */

/** At most this many room relays: the same bound as a link's relay hints. */
export const MAX_INVITATION_RELAYS = MAX_RELAY_HINTS

function isCanonicalRelayUrl(value: unknown): value is string {
  if (typeof value !== 'string' || !isSafeRelayUrl(value)) return false
  try {
    const parsed = new URL(value)
    if (parsed.username || parsed.password) return false
    return normalizeURL(value) === value
  } catch {
    return false
  }
}

/** True for a list of room relays the invitation may carry. Never throws. */
export function isInvitationRelays(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_INVITATION_RELAYS) return false
  return value.every(isCanonicalRelayUrl) && new Set(value).size === value.length
}

/** Throws unless `relays` is a list the invitation may carry; returns a copy. */
export function requireInvitationRelays(relays: readonly string[]): string[] {
  if (!Array.isArray(relays) || relays.length === 0) throw new Error('a room relay list needs at least one relay')
  if (relays.length > MAX_INVITATION_RELAYS) throw new Error(`a room can list at most ${MAX_INVITATION_RELAYS} relays`)
  for (const url of relays) {
    if (!isCanonicalRelayUrl(url)) throw new Error(`room relays must be wss:// URLs (ws:// only on localhost) in canonical form, without credentials: ${String(url)}`)
  }
  if (new Set(relays).size !== relays.length) throw new Error('room relays must not repeat')
  return [...relays]
}
