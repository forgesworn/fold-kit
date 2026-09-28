import { describe, it, expect } from 'vitest'
import { finalizeEvent, generateSecretKey, verifyEvent, verifiedSymbol, type Event } from 'nostr-tools/pure'
import { verifyEventUncached } from './verify.js'

function signed(content: string): Event {
  return finalizeEvent({ kind: 1, created_at: 1_800_000_000, tags: [], content }, generateSecretKey())
}

describe('verifyEventUncached', () => {
  it('accepts a genuinely signed event', () => {
    expect(verifyEventUncached(signed('hello'))).toBe(true)
  })

  it('rejects a tampered event', () => {
    const forged: Event = { ...signed('hello'), content: 'tampered' }
    expect(verifyEventUncached(forged)).toBe(false)
  })

  it('rejects a tampered event that arrives pre-marked verified', () => {
    const forged: Event = { ...signed('hello'), content: 'tampered' }
    forged[verifiedSymbol] = true
    // The unguarded call is the hazard this helper exists to close: it
    // returns the attacker's own cached verdict without checking anything.
    expect(verifyEvent(forged)).toBe(true)
    expect(verifyEventUncached(forged)).toBe(false)
  })

  it('leaves the caller’s event object unmodified', () => {
    const event = signed('hello')
    delete event[verifiedSymbol]
    verifyEventUncached(event)
    expect(event[verifiedSymbol]).toBeUndefined()
  })
})
