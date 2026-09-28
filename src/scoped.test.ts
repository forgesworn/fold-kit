import { describe, it, expect } from 'vitest'
import { deriveScoped } from './scoped.js'
import { deriveEpoch, generateEpochSecret } from './epoch.js'
import type { EpochKeys } from './epoch.js'

function epochKeys(epoch: number, secret = generateEpochSecret()): EpochKeys {
  return deriveEpoch({ epoch, secret })
}

describe('deriveScoped', () => {
  it('derives a 32-byte id and a 32-byte key for a valid label', () => {
    const epoch = epochKeys(1)
    const scoped = deriveScoped(epoch, 'example/v1/board/deadbeef/update')
    expect(scoped.id).toMatch(/^[0-9a-f]{64}$/)
    expect(scoped.key.length).toBe(32)
  })

  it('is deterministic: the same epoch key and label always derive the same pair', () => {
    const epoch = epochKeys(1)
    const a = deriveScoped(epoch, 'example/v1/board/deadbeef/update')
    const b = deriveScoped(epoch, 'example/v1/board/deadbeef/update')
    expect(a.id).toBe(b.id)
    expect(a.key).toEqual(b.key)
  })

  it('two different labels under the same epoch derive different pairs', () => {
    const epoch = epochKeys(1)
    const a = deriveScoped(epoch, 'example/v1/board/deadbeef/update')
    const b = deriveScoped(epoch, 'example/v1/board/deadbeef/pointer')
    expect(a.id).not.toBe(b.id)
    expect(a.key).not.toEqual(b.key)
  })

  it('the same label under two different epoch keys derives different pairs', () => {
    const e1 = epochKeys(1)
    const e2 = epochKeys(2)
    const a = deriveScoped(e1, 'example/v1/board/deadbeef/update')
    const b = deriveScoped(e2, 'example/v1/board/deadbeef/update')
    expect(a.id).not.toBe(b.id)
    expect(a.key).not.toEqual(b.key)
  })

  it('id and key are independently derived (never equal, never reused across id/key)', () => {
    const epoch = epochKeys(1)
    const scoped = deriveScoped(epoch, 'example/v1/board/deadbeef/update')
    expect(scoped.id).not.toBe(Buffer.from(scoped.key).toString('hex'))
  })

  it('epoch 0 works the same as any other epoch', () => {
    const epoch = epochKeys(0)
    const scoped = deriveScoped(epoch, 'example/v1/board/deadbeef/update')
    expect(scoped.id).toMatch(/^[0-9a-f]{64}$/)
  })

  // --- Refusals ---

  it('refuses a label in this kit\'s own protocol namespace', () => {
    const epoch = epochKeys(1)
    expect(() => deriveScoped(epoch, 'kithmoot/v1/epoch-id')).toThrow(/protocol namespace/)
  })

  it('refuses a label with no version segment', () => {
    const epoch = epochKeys(1)
    expect(() => deriveScoped(epoch, 'example/board/deadbeef/update')).toThrow(/label/)
  })

  it('refuses a label whose app namespace is not lower-case', () => {
    const epoch = epochKeys(1)
    expect(() => deriveScoped(epoch, 'Example/v1/board/deadbeef/update')).toThrow(/label/)
  })

  it('refuses an empty label', () => {
    const epoch = epochKeys(1)
    expect(() => deriveScoped(epoch, '')).toThrow(/label/)
  })

  it('refuses a label over 200 bytes after the version segment', () => {
    const epoch = epochKeys(1)
    const long = 'example/v1/' + 'a'.repeat(201)
    expect(() => deriveScoped(epoch, long)).toThrow(/label/)
  })

  it('accepts a label exactly 200 bytes after the version segment', () => {
    const epoch = epochKeys(1)
    const max = 'example/v1/' + 'a'.repeat(200)
    expect(() => deriveScoped(epoch, max)).not.toThrow()
  })

  it('refuses a label containing a raw space (e.g. a malformed board id embedded in it)', () => {
    const epoch = epochKeys(1)
    expect(() => deriveScoped(epoch, 'example/v1/board/not a valid uuid/update')).toThrow(/label/)
  })

  it('refuses an epoch key that is not 32 bytes', () => {
    expect(() => deriveScoped({ epoch: 1, id: 'a'.repeat(64), key: new Uint8Array(31) }, 'example/v1/x')).toThrow(/32 bytes/)
  })

  it('refuses a namespace segment over 64 bytes', () => {
    const epoch = epochKeys(1)
    expect(() => deriveScoped(epoch, `${'a'.repeat(65)}/v1/x`)).toThrow(/label/)
  })

  it('accepts a namespace segment of exactly 64 bytes', () => {
    const epoch = epochKeys(1)
    expect(() => deriveScoped(epoch, `${'a'.repeat(64)}/v1/x`)).not.toThrow()
  })

  it('refuses a version segment over 9 digits', () => {
    const epoch = epochKeys(1)
    expect(() => deriveScoped(epoch, `example/v${'9'.repeat(10)}/x`)).toThrow(/label/)
  })

  it('accepts a version segment of exactly 9 digits', () => {
    const epoch = epochKeys(1)
    expect(() => deriveScoped(epoch, `example/v${'9'.repeat(9)}/x`)).not.toThrow()
  })
})
