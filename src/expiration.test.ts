import { describe, expect, it } from 'vitest'
import { MAX_ROOM_ENDS_SECONDS, isRoomEnds, requireRoomEnds, withExpiration } from './expiration.js'

const NOW = 1_800_000_000
const ENDS = NOW + 86_400

describe('withExpiration', () => {
  it('leaves tags untouched, the same array, when the room has no end', () => {
    const tags = [['d', 'x'], ['expiration', String(NOW + 10)]]
    expect(withExpiration(tags, undefined)).toBe(tags)
  })

  it('adds the end to an event with no expiration, after its own tags', () => {
    expect(withExpiration([['d', 'x'], ['p', 'y']], ENDS)).toEqual([['d', 'x'], ['p', 'y'], ['expiration', String(ENDS)]])
    expect(withExpiration([], ENDS)).toEqual([['expiration', String(ENDS)]])
  })

  it('keeps an earlier expiration where it is, and lowers a later one to the end', () => {
    const earlier = [['p', 'y'], ['expiration', String(NOW + 60)], ['alt', 'z']]
    expect(withExpiration(earlier, ENDS)).toEqual(earlier)
    expect(withExpiration([['p', 'y'], ['expiration', String(ENDS + 1)], ['alt', 'z']], ENDS))
      .toEqual([['p', 'y'], ['expiration', String(ENDS)], ['alt', 'z']])
  })

  it('never returns two expirations, and ignores a malformed one', () => {
    const out = withExpiration([['expiration', String(ENDS + 5)], ['d', 'x'], ['expiration', String(NOW + 5)]], ENDS)
    expect(out).toEqual([['expiration', String(NOW + 5)], ['d', 'x']])
    expect(withExpiration([['expiration', 'soon']], ENDS)).toEqual([['expiration', String(ENDS)]])
  })

  it('does not mutate the tags it is given', () => {
    const tags = [['expiration', String(ENDS + 100)]]
    withExpiration(tags, ENDS)
    expect(tags).toEqual([['expiration', String(ENDS + 100)]])
  })

  it('refuses an end that is not a positive whole number of seconds', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => withExpiration([], bad)).toThrow(/positive whole number/)
    }
  })
})

describe('room ends', () => {
  it('isRoomEnds accepts positive safe integers only', () => {
    expect(isRoomEnds(ENDS)).toBe(true)
    for (const bad of [0, -5, 1.25, '1800086400', null, undefined, Number.POSITIVE_INFINITY]) expect(isRoomEnds(bad)).toBe(false)
  })

  it('requireRoomEnds wants an end after now and within thirty days of it', () => {
    expect(requireRoomEnds(ENDS, NOW)).toBe(ENDS)
    expect(requireRoomEnds(NOW + MAX_ROOM_ENDS_SECONDS, NOW)).toBe(NOW + MAX_ROOM_ENDS_SECONDS)
    expect(() => requireRoomEnds(NOW, NOW)).toThrow(/past/)
    expect(() => requireRoomEnds(NOW - 1, NOW)).toThrow(/past/)
    expect(() => requireRoomEnds(NOW + MAX_ROOM_ENDS_SECONDS + 1, NOW)).toThrow(/30 days/)
    expect(() => requireRoomEnds(ENDS + 0.5, NOW)).toThrow(/whole number/)
  })
})
