/**
 * NIP-40 expiration for a room that ends: a conference room.
 *
 * A conference room is a persistent group with a fixed end time. Every event
 * signed for it carries `['expiration', String(ends)]`, so relays that honour
 * NIP-40 drop the room's traffic once it has ended, rather than holding it
 * for as long as they keep anything. Not new in this kit: the shape is the
 * plain NIP-40 tag; what is decided here is how it meets an event that
 * already carries one of its own (a signal wrap, a call bell).
 */

/** The furthest ahead a conference room may end, from the moment it is
 *  created: thirty days. */
export const MAX_ROOM_ENDS_SECONDS = 30 * 24 * 60 * 60

/** True for a whole number of unix seconds a room could end at: a positive
 *  safe integer. Says nothing about whether it is in the future. */
export function isRoomEnds(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}

/** Throws unless `endsAt` is a valid end for a room created at `now`: after
 *  `now`, and no more than `MAX_ROOM_ENDS_SECONDS` beyond it. */
export function requireRoomEnds(endsAt: number, now: number): number {
  if (!isRoomEnds(endsAt)) throw new Error('a room end must be a positive whole number of seconds')
  if (endsAt <= now) throw new Error('a room cannot end in the past')
  if (endsAt > now + MAX_ROOM_ENDS_SECONDS) throw new Error('a room cannot end more than 30 days from now')
  return endsAt
}

/**
 * `tags` with the room's end applied as a NIP-40 expiration.
 *
 * An event with no expiration gains `['expiration', String(expiresAt)]`. One
 * that already expires earlier keeps its own: the room ending does not make
 * a short-lived event live longer. One that expires later is lowered to
 * `expiresAt`. Never more than one expiration tag comes back; any extra is
 * folded into the earliest. `expiresAt` undefined returns `tags` untouched,
 * the same array, so a room with no end signs exactly the bytes it always
 * did.
 */
export function withExpiration(tags: string[][], expiresAt: number | undefined): string[][] {
  if (expiresAt === undefined) return tags
  if (!isRoomEnds(expiresAt)) throw new Error('an expiration must be a positive whole number of seconds')
  let earliest = expiresAt
  let first = -1
  tags.forEach((tag, i) => {
    if (tag[0] !== 'expiration') return
    if (first === -1) first = i
    const own = Number(tag[1])
    if (isRoomEnds(own) && own < earliest) earliest = own
  })
  const out = tags.filter((tag, i) => tag[0] !== 'expiration' || i === first)
  const tag = ['expiration', String(earliest)]
  if (first === -1) return [...out, tag]
  return out.map((t) => (t[0] === 'expiration' ? tag : t))
}
