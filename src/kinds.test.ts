// Adapted from the "circle-layer kind numbers" describe block in KithMoot's
// src/api-surface.test.ts. That file's snapshot machinery (T0.2) tracks the
// whole KithMoot library surface and stays in KithMoot; this kit keeps only
// the kind-uniqueness check, against its own (smaller) KINDS object.
import { describe, expect, it } from 'vitest'
import { KINDS } from './kinds.js'

const CIRCLE_KIND_NAMES = [
  'CREDENTIAL',
  'INVITATION_REQUEST',
  'INVITATION_GRANT',
  'INVITATION_RETIREMENT',
  'GROUP_INVITATION',
  'ROOM_REKEY',
  'EPOCH_REQUEST',
  'EPOCH_GRANT',
] as const

describe('circle-layer kind numbers', () => {
  it('names exactly the 8 circle kinds this vector work covers, frozen to their current numbers', () => {
    expect(CIRCLE_KIND_NAMES).toHaveLength(8)
    expect(CIRCLE_KIND_NAMES.map((name) => KINDS[name])).toEqual([20460, 20466, 20467, 1461, 1463, 1462, 20468, 20469])
  })

  it('every kind number in KINDS is unique, including CHAT (shared with Girnel board events by design)', () => {
    const allValues = Object.values(KINDS)
    expect(new Set(allValues).size, 'KINDS has two names sharing one wire kind number').toBe(allValues.length)
  })

  it('every circle kind name named here is actually present in KINDS, so a rename here fails loudly rather than silently comparing undefined to undefined', () => {
    for (const name of CIRCLE_KIND_NAMES) expect(Object.prototype.hasOwnProperty.call(KINDS, name), name).toBe(true)
  })

  it('CHAT (1460) is present: Girnel board events share this kind so a relay cannot tell a board from a chat (plan Decision 3)', () => {
    expect(KINDS.CHAT).toBe(1460)
  })
})
