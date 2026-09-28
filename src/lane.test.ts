import { describe, it, expect } from 'vitest'
import { isDowngrade, isLane, laneOfRelayUrl, laneOfRelays, weakestLane, LANE_MEANING, LANES } from './lane.js'

describe('lane', () => {
  it('sheltered means a relay the circle runs; an onion on its own is public', () => {
    const circle = new Set(['wss://box.example', 'wss://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion'])
    expect(laneOfRelayUrl('wss://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion', circle)).toBe('sheltered')
    expect(laneOfRelayUrl('wss://box.example/', circle)).toBe('sheltered')
    expect(laneOfRelayUrl('wss://BOX.example', circle)).toBe('sheltered')
    expect(laneOfRelayUrl('ws://xyz.onion:8080')).toBe('public')
    expect(laneOfRelayUrl('ws://xyz.onion:8080', circle)).toBe('public')
    expect(laneOfRelayUrl('wss://relay.damus.io', circle)).toBe('public')
    expect(laneOfRelayUrl('not a url', circle)).toBe('public')
  })
  it('a set of relays is as weak as its weakest', () => {
    const circle = new Set(['wss://a.onion', 'wss://b.onion'])
    expect(laneOfRelays(['wss://a.onion', 'wss://relay.example'], circle)).toBe('public')
    expect(laneOfRelays(['wss://a.onion', 'wss://b.onion'], circle)).toBe('sheltered')
    expect(laneOfRelays(['wss://a.onion', 'wss://b.onion'])).toBe('public')
    expect(laneOfRelays([])).toBeUndefined()
    expect(weakestLane(['direct', 'sheltered'])).toBe('sheltered')
    expect(weakestLane(['direct'])).toBe('direct')
  })
  it('knows a downgrade from a match', () => {
    expect(isDowngrade('sheltered', 'public')).toBe(true)
    expect(isDowngrade('direct', 'sheltered')).toBe(true)
    expect(isDowngrade('public', 'sheltered')).toBe(false)
    expect(isDowngrade('public', 'public')).toBe(false)
  })
  it('every state has a fixed meaning and nothing else is a lane', () => {
    for (const lane of LANES) expect(LANE_MEANING[lane].length).toBeGreaterThan(10)
    expect(isLane('sheltered')).toBe(true)
    expect(isLane('private')).toBe(false)
  })
})
