// Recomputes vectors/fold-vectors.json (this kit's own T3.1/T3.3 vectors -
// see scripts/generate-fold.mjs) against `src/` directly, proving the JSON
// was not hand-edited into something the real functions no longer produce.
// Unlike vectors/verify.test.ts and vectors/verify-circle.test.ts (which
// verify files copied byte-identical from KithMoot), this file and its JSON
// belong to this kit alone. The forgesworn/kithmoot#205 fix and its vectors
// live on a separate branch/PR (fix/restamp-205) - this file and this
// branch's fold-vectors.json carry no credential.ts changes at all.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/hashes/utils'
import { getPublicKey, verifiedSymbol, type Event } from 'nostr-tools/pure'
import { deriveScoped } from '../src/scoped.js'
import { createSubKeyCertificate, verifySubKeyCertificate } from '../src/sub-cert.js'
import { verifyDeviceCredential } from '../src/credential.js'
import { deriveSecretKey, finalizeDeterministic, seed32 } from './lib/determinism.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, 'fold-vectors.json'), 'utf8'))

const EPOCH_KEYS: Record<number, Uint8Array> = {
  0: seed32('fold/epoch-0-key'),
  3: seed32('fold/epoch-3-key'),
}

function plain(event: Event) {
  const clone: Partial<Event> & { [k: symbol]: unknown } = { ...event }
  delete clone[verifiedSymbol]
  const { id, pubkey, created_at, kind, tags, content, sig } = clone as Event
  return { id, pubkey, created_at, kind, tags, content, sig }
}

describe('fold-vectors: deriveScoped (T3.1)', () => {
  for (const v of doc.groups.scoped.positive as Array<{
    boardId: string
    epoch: number
    name: string
    label: string
    output: { id: string; keyHex: string }
  }>) {
    it(`${v.label} @ epoch ${v.epoch}`, () => {
      const key = EPOCH_KEYS[v.epoch]!
      const scoped = deriveScoped({ epoch: v.epoch, id: 'unused', key }, v.label)
      expect(scoped.id).toBe(v.output.id)
      expect(bytesToHex(scoped.key)).toBe(v.output.keyHex)
    })
  }

  it('every positive id is unique across the whole vector set (no accidental collision)', () => {
    const ids = (doc.groups.scoped.positive as Array<{ output: { id: string } }>).map((v) => v.output.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  for (const v of doc.groups.scoped.refusals as Array<{ name: string; label: string; result: { threw: boolean; message?: string } }>) {
    it(`refusal: ${v.name}`, () => {
      const attempt = () => deriveScoped({ epoch: 0, id: 'unused', key: EPOCH_KEYS[0]! }, v.label)
      if (v.result.threw) {
        expect(attempt).toThrow(v.result.message)
      } else {
        expect(attempt).not.toThrow()
      }
    })
  }

  // Independent recompute: calls @noble/hashes' hkdf directly, bypassing
  // deriveScoped entirely, so this cannot pass merely because a bug in
  // deriveScoped is self-consistent with what the generator recorded (the
  // generator also calls deriveScoped, so without this, a shared bug in
  // deriveScoped and its labels/info-string handling could round-trip
  // undetected between generate-fold.mjs and this file).
  describe('independent HKDF recompute (no deriveScoped call)', () => {
    for (const v of doc.groups.scoped.positive as Array<{ label: string; epoch: number; output: { id: string; keyHex: string } }>) {
      it(`${v.label} @ epoch ${v.epoch}`, () => {
        const key = EPOCH_KEYS[v.epoch]!
        const id = bytesToHex(hkdf(sha256, key, undefined, `${v.label}/id`, 32))
        const derivedKey = bytesToHex(hkdf(sha256, key, undefined, `${v.label}/key`, 32))
        expect(id).toBe(v.output.id)
        expect(derivedKey).toBe(v.output.keyHex)
      })
    }
  })
})

describe('fold-vectors: sub-key certificate (T3.3)', () => {
  const g = doc.groups.subKeyCertificate as {
    input: { signerId: string; device: string; subKeyPubkey: string; expiresAt: number; now: number }
    credential: Event
    impostorCredential: Event
    output: { event: Event }
    verify: { positive: { opts: Record<string, unknown> } }
    refusals: Record<string, { event?: Event } & Record<string, unknown>>
  }
  const DEVICE_SK = deriveSecretKey('fold/device-a')
  const CERT_AUX_RAND = seed32('fold/cert-aux-rand')

  function positiveOpts(overrides: Record<string, unknown> = {}) {
    return { ...(g.verify.positive.opts as Record<string, unknown>), credential: g.credential, ...overrides }
  }

  it('the recorded certificate is byte-identical to a fresh mint under the same fixed inputs', async () => {
    const identity = {
      pubkey: getPublicKey(DEVICE_SK),
      async signEvent(unsigned: { kind: number; created_at: number; tags: string[][]; content: string }) {
        return finalizeDeterministic(unsigned, DEVICE_SK, CERT_AUX_RAND) as Event
      },
    }
    const cert = await createSubKeyCertificate({
      identity,
      signerId: g.input.signerId,
      subKeyPubkey: g.input.subKeyPubkey,
      expiresAt: g.input.expiresAt,
      now: () => g.input.now,
    })
    expect(plain(cert)).toEqual(plain(g.output.event))
  })

  it('verifies with matching options and the recorded credential', () => {
    const result = verifySubKeyCertificate(g.output.event, positiveOpts() as never)
    expect(result).toEqual({ ok: true, device: g.input.device, subKeyPubkey: g.input.subKeyPubkey })
  })

  // --- Structural negatives: every one re-signed, so each fails for
  // exactly the reason under test, not an incidental stale signature. ---

  it('refuses tags out of order', () => {
    const result = verifySubKeyCertificate(g.refusals.wrongOrder!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a renamed `d` tag at the correct position (kills the d-tag-name-only mutant)', () => {
    const result = verifySubKeyCertificate(g.refusals.renamedDTag!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a renamed `expiration` tag at the correct position (kills the expiration-tag-name-only mutant)', () => {
    const result = verifySubKeyCertificate(g.refusals.renamedExpirationTag!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a renamed `device` tag at the correct position (kills the device-tag-name-only mutant)', () => {
    const result = verifySubKeyCertificate(g.refusals.renamedDeviceTag!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a renamed `scope` tag at the correct position (kills the scope-tag-name-only mutant)', () => {
    const result = verifySubKeyCertificate(g.refusals.renamedScopeTag!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a scope other than "sub"', () => {
    const result = verifySubKeyCertificate(g.refusals.wrongScope!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'wrong scope' })
  })

  it('refuses a missing tag', () => {
    const result = verifySubKeyCertificate(g.refusals.tagMissing!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'wrong tag count' })
  })

  it('refuses an extra tag', () => {
    const result = verifySubKeyCertificate(g.refusals.tagExtra!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'wrong tag count' })
  })

  it('refuses a tag with an extra element', () => {
    const result = verifySubKeyCertificate(g.refusals.tagElementExtra!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'wrong tag shape' })
  })

  it('refuses non-empty content', () => {
    const result = verifySubKeyCertificate(g.refusals.nonEmptyContent!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'non-empty content' })
  })

  it('refuses an expiration with a leading zero', () => {
    const result = verifySubKeyCertificate(g.refusals.expirationLeadingZero!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'non-canonical expiration' })
  })

  it('refuses an expiration with a 0x prefix', () => {
    const result = verifySubKeyCertificate(g.refusals.expirationHexPrefix!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'non-canonical expiration' })
  })

  it('refuses an expiration with a fraction', () => {
    const result = verifySubKeyCertificate(g.refusals.expirationFraction!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'non-canonical expiration' })
  })

  it('refuses an expiration with leading whitespace', () => {
    const result = verifySubKeyCertificate(g.refusals.expirationWhitespace!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'non-canonical expiration' })
  })

  it('refuses a canonical expiration that simply does not equal the credential\'s', () => {
    const result = verifySubKeyCertificate(g.refusals.expirationUnequalToCredential!.event!, positiveOpts() as never)
    expect(result).toEqual({ ok: false, reason: 'expiration does not match the credential' })
  })

  // --- Verify-time parameter negatives ---

  it('refuses once expired', () => {
    const opts = positiveOpts({ now: g.refusals.expired!.now })
    const result = verifySubKeyCertificate(g.output.event, opts as never)
    expect(result).toEqual({ ok: false, reason: 'expired' })
  })

  it('refuses the wrong signer id (a different board/epoch scope)', () => {
    const opts = positiveOpts({ signerId: g.refusals.wrongSigner!.signerId })
    const result = verifySubKeyCertificate(g.output.event, opts as never)
    expect(result).toEqual({ ok: false, reason: 'wrong signer' })
  })

  it('refuses a sub-key pubkey mismatch (message signed by a different key than the certificate names)', () => {
    const opts = positiveOpts({ subKeyPubkey: g.refusals.wrongSubKeyPubkey!.subKeyPubkey })
    const result = verifySubKeyCertificate(g.output.event, opts as never)
    expect(result).toEqual({ ok: false, reason: 'device tag does not match the message signer' })
  })

  it('refuses the wrong credentialled device (an unrelated but validly-verified credential)', () => {
    const opts = positiveOpts({ credential: g.impostorCredential })
    const result = verifySubKeyCertificate(g.output.event, opts as never)
    expect(result).toEqual({ ok: false, reason: 'wrong device' })
  })
})

describe('fold-vectors: verifyDeviceCredential refuses a sub-key certificate outright', () => {
  const g = doc.groups.subCertAsDeviceCredential as {
    asIdentity: { ok: boolean; reason?: string }
    asRoomAcceptPerson: { ok: boolean; reason?: string }
  }
  const cert = (doc.groups.subKeyCertificate as { output: { event: Event } }).output.event
  const input = (doc.groups.subKeyCertificate as { input: { device: string; signerId: string; now: number } }).input

  it('as a person credential', () => {
    const result = verifyDeviceCredential(cert, { identity: input.device, now: input.now })
    expect(result).toEqual(g.asIdentity)
    expect(result).toEqual({ ok: false, reason: 'unknown scope' })
  })

  it('as a room credential with acceptPerson', () => {
    const result = verifyDeviceCredential(cert, { roomId: input.signerId, now: input.now, acceptPerson: true })
    expect(result).toEqual(g.asRoomAcceptPerson)
    expect(result).toEqual({ ok: false, reason: 'unknown scope' })
  })
})
