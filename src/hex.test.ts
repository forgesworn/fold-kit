import { describe, it, expect } from 'vitest'
import { hexEquals, normaliseHex } from './hex.js'

describe('hexEquals', () => {
  it('treats identical lower-case hex as equal', () => {
    expect(hexEquals('deadbeef', 'deadbeef')).toBe(true)
  })

  it('treats the same value in upper- and lower-case hex as equal', () => {
    expect(hexEquals('DEADBEEF', 'deadbeef')).toBe(true)
    expect(hexEquals('deadbeef', 'DEADBEEF')).toBe(true)
  })

  it('treats mixed-case hex as equal to either canonical case', () => {
    expect(hexEquals('DeAdBeEf', 'deadbeef')).toBe(true)
  })

  it('rejects genuinely different values regardless of case', () => {
    expect(hexEquals('deadbeef', 'deadbee0')).toBe(false)
    expect(hexEquals('DEADBEEF', 'deadbee0')).toBe(false)
  })
})

describe('normaliseHex', () => {
  it('lower-cases hex', () => {
    expect(normaliseHex('DEADBEEF')).toBe('deadbeef')
    expect(normaliseHex('DeAdBeEf')).toBe('deadbeef')
  })

  it('leaves already-lower-case hex unchanged', () => {
    expect(normaliseHex('deadbeef')).toBe('deadbeef')
  })

  it('makes two differently-cased spellings of the same identifier compare equal under `hexEquals` and sort identically under `<`', () => {
    const upper = 'DEADBEEF'
    const lower = 'deadbeef'
    expect(hexEquals(normaliseHex(upper), normaliseHex(lower))).toBe(true)
    expect(normaliseHex(upper) < normaliseHex('feedface')).toBe(normaliseHex(lower) < normaliseHex('feedface'))
  })
})
