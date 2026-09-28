import { verifyEvent, verifiedSymbol, type Event } from 'nostr-tools/pure'

/**
 * Verify an event's signature, ignoring any cached verdict it arrives with.
 *
 * `verifyEvent` caches its result on the event object under `verifiedSymbol`
 * and returns that cached value on any later call, without re-checking
 * anything. The property is an own enumerable symbol, so it survives a
 * shallow copy (`{ ...event }`, which is exactly how a caller might rebuild
 * an event after editing a field) - and an attacker who hands us an object
 * rather than a JSON string can simply set it themselves. Either way the
 * signature check silently becomes a no-op.
 *
 * Every inbound event in this library goes through here rather than calling
 * `verifyEvent` directly, so the defence cannot be forgotten by the next
 * decoder somebody writes. The copy also keeps the caller's object
 * unmodified: we never stamp a verdict onto something we did not sign.
 */
export function verifyEventUncached(event: Event): boolean {
  const unverified = { ...event }
  delete unverified[verifiedSymbol]
  return verifyEvent(unverified)
}

/**
 * Keep relay fan-out from verifying the same signed event once per relay and
 * replay. The cached value includes every signed field, so an object that
 * reuses a known id while changing its body or signature is rejected. The
 * fixed-size FIFO also prevents an untrusted relay from
 * growing keeper memory without bound.
 */
export function boundedEventVerifier(limit = 8_192, verify: (event: Event) => boolean = verifyEventUncached): (event: Event) => boolean {
  if (!Number.isSafeInteger(limit) || limit < 1) throw new Error('Event verification cache size must be a positive integer')
  const verified = new Map<string, string>()
  return event => {
    const cached = verified.get(event.id)
    if (cached !== undefined) {
      return cached === JSON.stringify([event.id, event.pubkey, event.created_at, event.kind, event.tags, event.content, event.sig])
    }
    if (!verify(event)) return false
    verified.set(event.id, JSON.stringify([event.id, event.pubkey, event.created_at, event.kind, event.tags, event.content, event.sig]))
    if (verified.size > limit) verified.delete(verified.keys().next().value!)
    return true
  }
}
