// Quiet automatic replies: the wait before a desk answers, and the limit on
// how often it refuses. New in this kit, not moved from KithMoot (see
// EXTRACTION.md "Quiet automatic replies").
//
// A desk that answers the instant a request lands, under a key that stays
// the same, tells anyone who can make it answer when the device holding
// that key is online and how quickly it is running ("Careless Whisper"
// style timing). Nothing here changes what a reply says: only whether one
// is sent, and when.

/** A wait range in milliseconds: `[min, max]`, drawn uniformly. */
export type ReplyDelayRange = readonly [min: number, max: number]

/** Run `fn` after `ms` milliseconds; the returned function cancels it. For
 *  tests, so a desk's wait is driven without real time passing. */
export type ReplySchedule = (fn: () => void, ms: number) => () => void

/** The wait before an automatic reply, unless the caller says otherwise. */
export const DEFAULT_REPLY_DELAY_MS: ReplyDelayRange = [500, 2000]

/** How long the authority desk waits before refusing the same participant
 *  again: a removed member asking with fresh requests learns nothing new
 *  from a second refusal inside it. */
export const REFUSE_AGAIN_AFTER_SECONDS = 3600

/** At most this many refusals a minute from one authority desk, whoever
 *  asks: a participant key is anyone's to mint, so a limit per participant
 *  alone does not stop a room-key holder asking as somebody new each time. */
export const MAX_REFUSALS_PER_MINUTE = 20

/** How many participants a refusal limiter remembers. The oldest is
 *  forgotten first; the per-minute budget still holds after that. */
export const REFUSAL_LIMITER_CAPACITY = 256

/** `setTimeout`, unreferenced so a pending reply never holds a process open. */
export const defaultReplySchedule: ReplySchedule = (fn, ms) => {
  const timer = setTimeout(fn, ms)
  ;(timer as unknown as { unref?: () => void }).unref?.()
  return () => clearTimeout(timer)
}

/** A wait drawn from `range`: whole milliseconds, never negative. A range
 *  that is not two finite numbers is read as no wait; one given backwards
 *  is put the right way round. */
export function replyDelay(range: ReplyDelayRange, random: () => number = Math.random): number {
  const [a, b] = range
  if (!Number.isFinite(a) || !Number.isFinite(b)) return 0
  const min = Math.max(0, Math.min(a, b))
  const max = Math.max(0, a, b)
  if (max <= min) return Math.floor(min)
  const r = random()
  const unit = Number.isFinite(r) ? Math.min(Math.max(r, 0), 1) : 0
  return Math.floor(min + unit * (max - min))
}

export interface RefusalLimiterOptions {
  /** Refusals allowed in any 60 seconds, across every key. Default
   *  `MAX_REFUSALS_PER_MINUTE`. */
  perMinute?: number
  /** Keys remembered. Default `REFUSAL_LIMITER_CAPACITY`. */
  capacity?: number
}

/** Decides whether a refusal goes on the wire: once per key per `every`
 *  seconds, and no more than `perMinute` in any minute overall. Memory is
 *  bounded by `capacity` keys plus `perMinute` timestamps. */
export class RefusalLimiter {
  readonly #last = new Map<string, number>()
  readonly #sent: number[] = []
  readonly #perMinute: number
  readonly #capacity: number

  constructor(opts: RefusalLimiterOptions = {}) {
    this.#perMinute = Math.max(0, Math.floor(opts.perMinute ?? MAX_REFUSALS_PER_MINUTE))
    this.#capacity = Math.max(1, Math.floor(opts.capacity ?? REFUSAL_LIMITER_CAPACITY))
  }

  /** Keys remembered now. */
  get size(): number {
    return this.#last.size
  }

  /** True, and recorded, when a refusal to `key` may be sent at `now`
   *  (unix seconds); false leaves nothing recorded. */
  allow(key: string, every: number, now: number): boolean {
    const last = this.#last.get(key)
    if (last !== undefined && now - last < every) return false
    while (this.#sent.length > 0 && now - this.#sent[0]! >= 60) this.#sent.shift()
    if (this.#sent.length >= this.#perMinute) return false
    this.#sent.push(now)
    // Re-inserted so the map's order is oldest-refused first.
    this.#last.delete(key)
    this.#last.set(key, now)
    if (this.#last.size > this.#capacity) this.#last.delete(this.#last.keys().next().value!)
    return true
  }

  /** Forget `key`, as when the participant is granted. */
  forget(key: string): void {
    this.#last.delete(key)
  }
}
