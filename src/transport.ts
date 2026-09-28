import type { Event } from 'nostr-tools/pure'
import type { Filter } from 'nostr-tools/filter'

/**
 * The relay transport seam the kit's codecs need: publish, subscribe, close.
 *
 * This is the kit's own declaration, not an import of KithMoot's
 * `RelayTransport` (KithMoot's `src/relay-pool.ts`). The relay pool itself has
 * not moved to the kit yet (see docs/plans/2026-09-28-circle-kit-extraction.md
 * "Corrections after the T0 vector review", and §1.1's `relay` subpath row,
 * in the girnel repository): epoch, invitation and persistent-invitation only
 * ever call `publish`/`subscribe`/`close` on the transport they are given, so
 * the kit needs only that much of the shape, not KithMoot's richer
 * `describe()`/`rekey()` extensions.
 *
 * A caller can pass KithMoot's `NostrRelayPool` (which implements a superset
 * of this interface) straight through, or the kit's own `SimTransport`
 * (`test/sim-relay.ts`), or any other implementation with the same three
 * methods.
 */
export interface RelayTransport {
  publish(event: Event): Promise<void>
  /** `via` is the relay URL that delivered the event, when the transport
   *  knows it. */
  subscribe(filters: Filter[], onEvent: (event: Event, via?: string) => void, onEose?: () => void): () => void
  close(): void
}
