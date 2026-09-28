import type { Event } from 'nostr-tools/pure'
import type { Filter } from 'nostr-tools/filter'
import type { RelayTransport } from '../src/transport.js'

type Handler = (event: Event) => void

interface Subscription {
  filters: Filter[]
  handler: Handler
}

function matches(event: Event, filter: Filter): boolean {
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false
  if (filter.ids && !filter.ids.includes(event.id)) return false
  if (filter.since !== undefined && event.created_at < filter.since) return false
  if (filter.until !== undefined && event.created_at > filter.until) return false

  for (const [key, wanted] of Object.entries(filter)) {
    if (!key.startsWith('#')) continue
    const tagName = key.slice(1)
    const values = event.tags.filter((t) => t[0] === tagName).map((t) => t[1])
    if (!(wanted as string[]).some((w) => values.includes(w))) return false
  }
  return true
}

/** NIP-01: kinds from 20000 are ephemeral and never stored. */
const EPHEMERAL_FROM = 20_000

/**
 * An in-process relay honouring enough of NIP-01 to run full journeys with no
 * network. Ephemeral kinds are delivered but never replayed, which is what
 * makes it a fair test of signalling. With `replay`, stored kinds are
 * replayed to a new subscriber the way a real relay replays them - which is
 * what a durable rekey event exists for - and ephemeral kinds still are not.
 */
export class SimRelay {
  readonly published: Event[] = []
  #subs = new Set<Subscription>()
  #closed = false
  readonly #replay: boolean

  constructor(opts: { replay?: boolean } = {}) {
    this.#replay = opts.replay === true
  }

  publish(event: Event): void {
    if (this.#closed) throw new Error('relay is closed')
    this.published.push(event)
    for (const sub of this.#subs) {
      if (sub.filters.some((f) => matches(event, f))) sub.handler(event)
    }
  }

  subscribe(filters: Filter[], handler: Handler): () => void {
    if (this.#closed) throw new Error('relay is closed')
    const sub: Subscription = { filters, handler }
    this.#subs.add(sub)
    if (this.#replay) {
      for (const event of this.published) {
        if (event.kind >= EPHEMERAL_FROM) continue
        if (filters.some((f) => matches(event, f))) handler(event)
      }
    }
    return () => this.#subs.delete(sub)
  }

  close(): void {
    this.#closed = true
    this.#subs.clear()
  }
}

/** The simulator behind the RelayTransport seam. */
export class SimTransport implements RelayTransport {
  #relay: SimRelay
  #closed = false

  constructor(relay: SimRelay) {
    this.#relay = relay
  }

  async publish(event: Event): Promise<void> {
    if (this.#closed) throw new Error('transport is closed')
    this.#relay.publish(event)
  }

  subscribe(filters: Filter[], onEvent: (event: Event) => void, onEose?: () => void): () => void {
    if (this.#closed) throw new Error('transport is closed')
    const off = this.#relay.subscribe(filters, onEvent)
    onEose?.()
    return off
  }

  close(): void {
    this.#closed = true
  }
}
