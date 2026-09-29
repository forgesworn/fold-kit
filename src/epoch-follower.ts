import type { Event } from 'nostr-tools/pure'
import type { Filter } from 'nostr-tools/filter'
import { KINDS } from './kinds.js'
import { MAX_EPOCH, type EpochKeys, type PeekRekeyOptions, type RekeyNotice } from './epoch.js'
import { decodeRekeyEnvelope, MAX_REKEY_CONTENT_LENGTH, type RekeyEnvelope } from './rekey-reader.js'
import { assertCompleteStoredQuery, type StoredEventQuery, type StoredEventQueryResult } from './stored-query.js'
import type { RelayTransport } from './transport.js'

const HEX64 = /^[0-9a-f]{64}$/i
const HEX128 = /^[0-9a-f]{128}$/i
/** A bounded stored result. Overflow is incomplete and must be fetched again. */
export const MAX_FOLLOWER_CANDIDATES = 256
export const MAX_FOLLOWER_BYTES = 8 * 1024 * 1024

export interface EpochTransition {
  kind: 'advance' | 'replace'
  parentEpoch: number
  /** Exact signed winner, copied from the stored-query result. */
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

/**
 * Selects lowest-id complete rekeys without owning storage, sockets or signing.
 * A trusted initial checkpoint is the lower bound when earlier keys/winner ids
 * are unavailable. To detect earlier forks, keep their parent keys and winner
 * ids through the injected lookups. Every adoption awaits caller persistence.
 */
export class EpochFollower {
  readonly #opts: EpochFollowerOptions
  readonly #filters: Filter[]
  #epoch: number
  #winnerIds = new Map<number, string>()
  #unsubscribe?: () => void
  #closed = false
  #started = false
  #serial?: Promise<StoredEventQueryResult>
  #abort?: AbortController
  #liveVersion = 0
  #attemptVersion = 0

  constructor(options: EpochFollowerOptions) {
    if (!Number.isSafeInteger(options.initial.epoch) || options.initial.epoch < 0 ||
        options.initial.epoch > MAX_EPOCH || !HEX64.test(options.roomId) ||
        !HEX64.test(options.authority) || (options.initial.winningRekeyId !== undefined &&
        !HEX64.test(options.initial.winningRekeyId))) throw new TypeError('invalid epoch follower context')
    this.#opts = { ...options, roomId: options.roomId.toLowerCase(), authority: options.authority.toLowerCase() }
    this.#epoch = options.initial.epoch
    if (options.initial.winningRekeyId) this.#winnerIds.set(this.#epoch, options.initial.winningRekeyId.toLowerCase())
    this.#filters = [{ kinds: [KINDS.ROOM_REKEY], authors: [this.#opts.authority], '#d': [this.#opts.roomId] }]
  }

  /** Subscribe to live hints; the stored query, not a transport EOSE, decides completeness. */
  start(): void {
    if (this.#closed) throw new Error('epoch follower is closed')
    if (this.#started) return
    this.#started = true
    this.#unsubscribe = this.#opts.transport.subscribe(this.#filters, (event) => {
      if (this.#closed || !plausible(event, this.#opts.roomId, this.#opts.authority)) return
      this.#liveVersion++
      // A live event is a hint to refetch the complete stored fork set.
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
      const version = this.#liveVersion
      this.#attemptVersion = version
      const events = new Map<string, Event>()
      let bytes = 0
      let overflow = false
      let accepting = true
      const result = await this.#opts.query(this.#filters, (event) => {
        if (!accepting || overflow || this.#closed || signal.aborted ||
            !plausible(event, this.#opts.roomId, this.#opts.authority) || events.has(event.id)) return
        const size = eventBytes(event)
        if (events.size >= MAX_FOLLOWER_CANDIDATES || bytes + size > MAX_FOLLOWER_BYTES) {
          overflow = true; return
        }
        bytes += size
        events.set(event.id, copyEvent(event))
      }, signal)
      accepting = false
      if (this.#closed || signal.aborted) throw new Error('epoch follower cancelled')
      assertCompleteStoredQuery(result)
      if (overflow) throw new Error('stored rekey result is incomplete: candidate bound exceeded')
      if (version !== this.#liveVersion) continue
      const decision = await this.#choose([...events.values()], signal)
      if (decision === 'refetch' || version !== this.#liveVersion) continue
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
      if (!parent || parent.epoch !== epoch - 1) {
        if (oldId) throw new Error(`parent keys for entered epoch ${epoch} are unavailable`)
        continue
      }
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
      for (const key of this.#winnerIds.keys()) if (key > epoch) this.#winnerIds.delete(key)
      this.#winnerIds.set(epoch, winner.event.id)
      if (change.kind === 'replace') return 'refetch'
    }
    return 'stable'
  }
}
