import type { Event } from 'nostr-tools/pure'

/** Per-event ceiling of the strict evidence carrier, in canonical UTF-8 bytes. */
export const MAX_PERSISTENT_INVITATION_EVENT_BYTES = 16_384
/** Tag arrays a strict evidence carrier may hold, and strings in each. */
export const MAX_EVIDENCE_CARRIER_TAGS = 64
export const MAX_EVIDENCE_CARRIER_TAG_STRINGS = 8

/** Returns `event` if the strict evidence reader could retain it, else throws.
 * A writer calls this before it signs and publishes, so the authority never
 * signs what a strict reader must refuse. */
export function requireEvidenceCarrierLimits(event: Event, what: string): Event {
  const bytes = new TextEncoder().encode(JSON.stringify({ id: event.id, pubkey: event.pubkey, created_at: event.created_at,
    kind: event.kind, tags: event.tags, content: event.content, sig: event.sig })).length
  if (bytes > MAX_PERSISTENT_INVITATION_EVENT_BYTES) {
    throw new Error(`the ${what} is ${bytes} bytes, over the ${MAX_PERSISTENT_INVITATION_EVENT_BYTES} a strict reader accepts; use fewer or shorter relays or storage nodes`)
  }
  if (event.tags.length > MAX_EVIDENCE_CARRIER_TAGS || event.tags.some(tag => tag.length > MAX_EVIDENCE_CARRIER_TAG_STRINGS)) {
    throw new Error(`the ${what} has more tags, or more strings in a tag, than a strict reader accepts`)
  }
  return event
}
