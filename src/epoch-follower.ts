import type { Event } from 'nostr-tools/pure'
import type { Filter } from 'nostr-tools/filter'
import { KINDS } from './kinds.js'
import { MAX_EPOCH, type EpochKeys, type PeekRekeyOptions, type RekeyNotice } from './epoch.js'
import { decodeRekeyEnvelope, MAX_REKEY_CONTENT_LENGTH, type RekeyEnvelope } from './rekey-reader.js'
import { assertCompleteStoredQuery, type StoredEventQuery, type StoredEventQueryResult } from './stored-query.js'
import type { RelayTransport } from './transport.js'
import { verifyEventUncached } from './verify.js'

const HEX64 = /^[0-9a-f]{64}$/i
const HEX128 = /^[0-9a-f]{128}$/i
/** A bounded stored result. Overflow is incomplete and must be fetched again. */
export const MAX_FOLLOWER_CANDIDATES = 256
export const MAX_FOLLOWER_BYTES = 8 * 1024 * 1024

export interface EpochTransition {
  kind: 'advance' | 'replace'
  parentEpoch: number
  /** Exact signed winner, copied from a live or stored delivery. */
  event: Event
  previousWinnerId?: string
  /** Missing recipient copy is a valid winner without a secret. */
  notice: RekeyNotice
  /** The caller must discard descendants of the losing winner before resolving. */
  invalidateFromEpoch?: number
}

export interface EpochFollowerOptions extends PeekRekeyOptions {
  transport: RelayTransport
  query: StoredEventQuery
  initial: { epoch: number; winningRekeyId?: string }
  /** Parent keys must remain available to inspect earlier forks. */
  epochKeys(epoch: number): EpochKeys | undefined
  /** Durable winner-id lookup for entered epochs, including historical parents. */
  winningRekeyId(epoch: number): string | undefined
  /** Called only for the chosen, complete-body winner after real query EOSE. */
  openSecret(event: Event, envelope: RekeyEnvelope): Promise<Uint8Array | undefined>
  /** Resolves only after the caller has durably stored the transition. */
  onTransition(change: EpochTransition): Promise<void>
  onError?(error: unknown): void
}

function plausible(event: Event, roomId: string, authority: string): boolean {
  return !!event && event.kind === KINDS.ROOM_REKEY &&
    typeof event.id === 'string' && HEX64.test(event.id) &&
    typeof event.sig === 'string' && HEX128.test(event.sig) &&
    event.pubkey === authority && typeof event.content === 'string' &&
    event.content.length <= MAX_REKEY_CONTENT_LENGTH &&
    Number.isSafeInteger(event.created_at) && event.created_at >= 0 &&
    Array.isArray(event.tags) && event.tags.length === 2 &&
    Array.isArray(event.tags[0]) && event.tags[0]!.length === 2 &&
    event.tags[0]![0] === 'd' && event.tags[0]![1] === roomId &&
    Array.isArray(event.tags[1]) && event.tags[1]!.length === 2 &&
    event.tags[1]![0] === 'epoch' &&
    typeof event.tags[1]![1] === 'string' && /^[1-9][0-9]{0,6}$/.test(event.tags[1]![1]!) &&
    Number(event.tags[1]![1]) <= MAX_EPOCH
}

function copyEvent(event: Event): Event {
  return { ...event, tags: event.tags.map((tag) => [...tag]) }
}

function eventBytes(event: Event): number {
  return event.content.length + event.id.length + event.sig.length + event.pubkey.length +
    event.tags.reduce((total, tag) => total + tag.reduce((n, field) => n + field.length, 0), 0)
}

function sameEvent(a: Event, b: Event): boolean {
  return a.id === b.id && a.sig === b.sig && a.pubkey === b.pubkey &&
    a.kind === b.kind && a.created_at === b.created_at && a.content === b.content &&
    a.tags.length === b.tags.length && a.tags.every((tag, i) =>
      tag.length === b.tags[i]!.length && tag.every((field, j) => field === b.tags[i]![j]))
}

/**
 * Selects lowest-id complete rekeys without owning storage, sockets or signing.
 * A trusted initial checkpoint is the lower bound when earlier keys/winner ids
 * are unavailable. To detect earlier forks, keep their parent keys and winner
 * ids through the injected lookups. Every adoption awaits caller persistence.
 */
export class EpochFollower {
  readonly #opts: EpochFollowerOptions
  readonly #filters: Filter[]
  readonly #initialEpoch: number
  #checkedParents = new Set<number>()
  #epoch: number
  #winnerIds = new Map<number, string>()
  #unsubscribe?: () => void
  #closed = false
  #started = false
  #serial?: Promise<StoredEventQueryResult>
  #abort?: AbortController
  #liveVersion = 0
  #attemptVersion = 0
  #liveCandidates: Event[] = []
  #liveBytes = 0
  #liveOverflow = false
  #overflowGeneration = 0
  #overflowSources = new Set<string>()

  constructor(options: EpochFollowerOptions) {
    if (!Number.isSafeInteger(options.initial.epoch) || options.initial.epoch < 0 ||
        options.initial.epoch > MAX_EPOCH || !HEX64.test(options.roomId) ||
        !HEX64.test(options.authority) || (options.initial.winningRekeyId !== undefined &&
        !HEX64.test(options.initial.winningRekeyId))) throw new TypeError('invalid epoch follower context')
    this.#opts = { ...options, roomId: options.roomId.toLowerCase(), authority: options.authority.toLowerCase() }
    this.#epoch = options.initial.epoch
    this.#initialEpoch = options.initial.epoch
    if (options.initial.winningRekeyId) this.#winnerIds.set(this.#epoch, options.initial.winningRekeyId.toLowerCase())
    this.#filters = [{ kinds: [KINDS.ROOM_REKEY], authors: [this.#opts.authority], '#d': [this.#opts.roomId] }]
  }

  /** Subscribe to bounded live candidates; only a stored-query EOSE decides completeness. */
  start(): void {
    if (this.#closed) throw new Error('epoch follower is closed')
    if (this.#started) return
    this.#started = true
    this.#unsubscribe = this.#opts.transport.subscribe(this.#filters, (event, via) => {
      if (this.#closed || !plausible(event, this.#opts.roomId, this.#opts.authority)) return
      // A live delivery is an observed candidate even when a later stored
      // query omits it. Only exact duplicates can be suppressed before auth:
      // a forged copy with the same claimed id must not hide authentic bytes.
      if (this.#liveCandidates.some((candidate) => sameEvent(candidate, event))) return
      const size = eventBytes(event)
      if (this.#liveCandidates.length >= MAX_FOLLOWER_CANDIDATES ||
          this.#liveBytes + size > MAX_FOLLOWER_BYTES) {
        this.#liveOverflow = true
        this.#overflowGeneration++
        if (via) this.#overflowSources.add(via)
      }
      else { this.#liveCandidates.push(copyEvent(event)); this.#liveBytes += size }
      this.#liveVersion++
      // The query supplies completion evidence and any competing stored forks.
      if (!this.#serial) this.#startBackgroundQuery()
    })
  }

  /** Concurrent requests share one serial reconciliation. Failure leaves the durable checkpoint intact. */
  catchUp(): Promise<StoredEventQueryResult> {
    if (this.#closed) return Promise.reject(new Error('epoch follower is closed'))
    if (this.#serial) return this.#serial
    const controller = new AbortController()
    this.#abort = controller
    const work = this.#reconcile(controller.signal)
    const settled = work.finally(() => {
      if (this.#serial === settled) {
        this.#serial = undefined
        if (!this.#closed && this.#liveVersion > this.#attemptVersion) this.#startBackgroundQuery()
      }
      if (this.#abort === controller) this.#abort = undefined
    })
    this.#serial = settled
    return settled
  }

  #startBackgroundQuery(): void {
    void this.catchUp().catch((error: unknown) => {
      try { this.#opts.onError?.(error) } catch { /* caller error hooks do not own the follower */ }
    })
  }

  #retainLive(keep: (event: Event) => boolean): void {
    this.#liveCandidates = this.#liveCandidates.filter(keep)
    this.#liveBytes = this.#liveCandidates.reduce((total, event) => total + eventBytes(event), 0)
  }

  #pruneInvalidLive(): void {
    // The queue was bounded before signature work. A forged claimed id cannot
    // suppress authentic bytes, and definitively bad signatures must not hold
    // the bounded queue forever after a completed catch-up.
    this.#retainLive((event) => {
      try { return verifyEventUncached(event) } catch { return false }
    })
  }

  close(): void {
    if (this.#closed) return
    this.#closed = true
    this.#abort?.abort()
    this.#unsubscribe?.()
    this.#unsubscribe = undefined
    // The transport may be shared with other users; it is not owned here.
  }

  async #reconcile(signal: AbortSignal): Promise<StoredEventQueryResult> {
    // A replacement must refetch descendants under its new parent context.
    // Repeated live arrivals are bounded; a partial pass never reports success.
    for (let attempt = 0; attempt < MAX_FOLLOWER_CANDIDATES; attempt++) {
      if (this.#closed || signal.aborted) throw new Error('epoch follower cancelled')
      this.#pruneInvalidLive()
      const version = this.#liveVersion
      this.#attemptVersion = version
      const events = this.#liveCandidates.map(copyEvent)
      let bytes = this.#liveBytes
      let overflow = false
      const lostLiveCandidate = this.#liveOverflow
      const overflowGeneration = this.#overflowGeneration
      let accepting = true
      const result = await this.#opts.query(this.#filters, (event) => {
        if (!accepting || overflow || this.#closed || signal.aborted ||
            !plausible(event, this.#opts.roomId, this.#opts.authority) ||
            events.some((candidate) => sameEvent(candidate, event))) return
        const size = eventBytes(event)
        if (events.length >= MAX_FOLLOWER_CANDIDATES || bytes + size > MAX_FOLLOWER_BYTES) {
          overflow = true; return
        }
        bytes += size
        events.push(copyEvent(event))
      }, signal)
      accepting = false
      if (this.#closed || signal.aborted) throw new Error('epoch follower cancelled')
      assertCompleteStoredQuery(result)
      if (overflow) throw new Error('stored rekey result is incomplete: candidate bound exceeded')
      // A live delivery after this query began may have overflowed the queue.
      // Its missing bytes cannot be recovered by this older stored result.
      if (version !== this.#liveVersion || overflowGeneration !== this.#overflowGeneration) continue
      // If a live candidate was dropped at the bound, only a full no-since
      // refetch from every queried source can repair the incomplete view.
      if (lostLiveCandidate) {
        if (result.unavailable.length || [...this.#overflowSources].some((source) => !result.eosed.includes(source))) {
          throw new Error('live rekey overflow needs a complete stored refetch')
        }
        this.#liveOverflow = false
        this.#overflowSources.clear()
      }
      const decision = await this.#choose(events, signal)
      if (decision === 'refetch' || version !== this.#liveVersion) continue
      // A descendant accepted under today's parent may remain the minimum
      // under a later, lower parent fork with the same epoch secret. Even a
      // complete query can omit a live event, so keep signed live evidence.
      // The queue remains bounded; overflow requires a complete refetch and
      // cannot silently choose a higher candidate.
      return result
    }
    throw new Error('stored rekey result changed during reconciliation; refetch needed')
  }

  #winnerId(epoch: number): string | undefined {
    const value = this.#winnerIds.get(epoch) ?? this.#opts.winningRekeyId(epoch)
    if (value !== undefined && !HEX64.test(value)) throw new TypeError('invalid persisted winner id')
    return value?.toLowerCase()
  }

  async #choose(events: Event[], signal: AbortSignal): Promise<'refetch' | 'stable'> {
    const epochs = [...new Set(events.map((event) => Number(event.tags[1]![1])))].sort((a, b) => a - b)
    for (const epoch of epochs) {
      if (epoch > this.#epoch + 1) break
      if (this.#closed || signal.aborted) throw new Error('epoch follower cancelled')
      const oldId = epoch <= this.#epoch ? this.#winnerId(epoch) : undefined
      const parent = this.#opts.epochKeys(epoch - 1)
      if (parent !== undefined && (!parent || parent.epoch !== epoch - 1)) {
        throw new TypeError(`parent keys for entered epoch ${epoch} are malformed`)
      }
      if (!parent) {
        // A restored checkpoint may legitimately have no earlier keys. It does
        // not promise fork verification before that trust boundary. Once this
        // instance has inspected a parent, losing it is no longer a checkpoint.
        if (epoch <= this.#initialEpoch && !this.#checkedParents.has(epoch)) continue
        if (oldId || this.#checkedParents.has(epoch)) throw new Error(`parent keys for entered epoch ${epoch} are unavailable`)
        continue
      }
      this.#checkedParents.add(epoch)
      let winner: { event: Event; envelope: RekeyEnvelope } | undefined
      for (const event of events) {
        if (Number(event.tags[1]![1]) !== epoch || (winner && event.id >= winner.event.id)) continue
        const envelope = decodeRekeyEnvelope(event, { roomId: this.#opts.roomId,
          authority: this.#opts.authority, current: parent })
        if (envelope) winner = { event, envelope }
      }
      if (!winner) continue
      if (epoch <= this.#epoch && (!oldId || winner.event.id >= oldId)) continue
      const version = this.#liveVersion
      const secret = await this.#opts.openSecret(winner.event, winner.envelope)
      if (this.#closed || signal.aborted) throw new Error('epoch follower cancelled')
      if (version !== this.#liveVersion) return 'refetch'
      if (secret !== undefined && (!(secret instanceof Uint8Array) || secret.length !== 32)) {
        throw new TypeError('opened epoch secret must be 32 bytes')
      }
      const notice: RekeyNotice = { ...winner.envelope.notice,
        ...(secret === undefined ? {} : { secret: secret.slice() }) }
      const change: EpochTransition = epoch <= this.#epoch
        ? { kind: 'replace', parentEpoch: epoch - 1, event: copyEvent(winner.event),
            previousWinnerId: oldId, notice, invalidateFromEpoch: epoch + 1 }
        : { kind: 'advance', parentEpoch: epoch - 1, event: copyEvent(winner.event), notice }
      await this.#opts.onTransition(change)
      if (this.#closed || signal.aborted) throw new Error('epoch follower cancelled')
      this.#epoch = epoch
      if (change.kind === 'replace') {
        for (const checked of this.#checkedParents) if (checked > epoch) this.#checkedParents.delete(checked)
      }
      for (const key of this.#winnerIds.keys()) if (key > epoch) this.#winnerIds.delete(key)
      this.#winnerIds.set(epoch, winner.event.id)
      if (change.kind === 'replace' || version !== this.#liveVersion) return 'refetch'
    }
    return 'stable'
  }
}
