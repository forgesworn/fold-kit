// Regression tests for forgesworn/kithmoot#205 (see EXTRACTION.md "The #205
// fix" and scripts/diff-source.mjs's declared-diff check). Kept as its own
// file, rather than added to credential.test.ts, because credential.test.ts
// is otherwise an unchanged copy of KithMoot's own test file (EXTRACTION.md).
import { describe, it, expect } from 'vitest'
import { generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure'
import { createDeviceCredential, verifyDeviceCredential, PERSON_CREDENTIAL_MAX_SECONDS, RestampedCredentialExpiryError } from './credential.js'

const NOW = 1_800_000_000

/** A `ParticipantIdentity` whose signer restamps `created_at` to its own,
 *  earlier clock - the exact shape of the bug: a bunker or phone signer that
 *  disagrees with the caller's clock. */
function restampingIdentity(participantSk: Uint8Array, restampBy: number) {
  const pubkey = getPublicKey(participantSk)
  return {
    pubkey,
    async signEvent(unsigned: { kind: number; created_at: number; tags: string[][]; content: string }): Promise<Event> {
      const { finalizeEvent } = await import('nostr-tools/pure')
      return finalizeEvent({ ...unsigned, created_at: unsigned.created_at - restampBy }, participantSk)
    },
  }
}

describe('forgesworn/kithmoot#205: a restamping signer and the 30-day cap', () => {
  it('before the fix, a credential asked for at the full 30 days and restamped 10s earlier would verify as too long (documents the bug this guards against)', async () => {
    // Demonstrates the underlying arithmetic mismatch directly, without
    // going through createDeviceCredential's new guard: mint checked
    // `expiresAt - now`, verify checks `expiresAt - cred.created_at`. A
    // restamp shifts only the second.
    const now = NOW
    const expiresAt = now + PERSON_CREDENTIAL_MAX_SECONDS
    const restampedCreatedAt = now - 10
    expect(expiresAt - now).toBeLessThanOrEqual(PERSON_CREDENTIAL_MAX_SECONDS) // what mint checked
    expect(expiresAt - restampedCreatedAt).toBeGreaterThan(PERSON_CREDENTIAL_MAX_SECONDS) // what verify checks
  })

  it('createDeviceCredential now fails loudly, at mint time, when a restamp would make the credential unverifiable everywhere', async () => {
    const participantSk = generateSecretKey()
    const identity = restampingIdentity(participantSk, 10)
    await expect(
      createDeviceCredential({
        identity,
        devicePubkey: getPublicKey(generateSecretKey()),
        scope: 'person',
        expiresAt: NOW + PERSON_CREDENTIAL_MAX_SECONDS,
        now: () => NOW,
      }),
    ).rejects.toThrow(RestampedCredentialExpiryError)
  })

  it('the thrown error is typed, named, and reports exactly how far over the cap the restamp pushed the expiry', async () => {
    const participantSk = generateSecretKey()
    const identity = restampingIdentity(participantSk, 10)
    let thrown: unknown
    try {
      await createDeviceCredential({
        identity,
        devicePubkey: getPublicKey(generateSecretKey()),
        scope: 'person',
        expiresAt: NOW + PERSON_CREDENTIAL_MAX_SECONDS,
        now: () => NOW,
      })
    } catch (err) {
      thrown = err
    }
    expect(thrown).toBeInstanceOf(RestampedCredentialExpiryError)
    const err = thrown as RestampedCredentialExpiryError
    expect(err.name).toBe('RestampedCredentialExpiryError')
    expect(err.overBySeconds).toBe(10)
    expect(err.message).toMatch(/restamped created_at/)
  })

  it('a caller that asks for a shorter margin (as the downstream sync spec\'s retry does) succeeds even with the same restamp', async () => {
    const participantSk = generateSecretKey()
    const identity = restampingIdentity(participantSk, 10)
    const cred = await createDeviceCredential({
      identity,
      devicePubkey: getPublicKey(generateSecretKey()),
      scope: 'person',
      // one hour of margin, as the downstream sync spec's #205 retry does
      expiresAt: NOW + PERSON_CREDENTIAL_MAX_SECONDS - 3600,
      now: () => NOW,
    })
    const result = verifyDeviceCredential(cred, { identity: identity.pubkey, now: NOW })
    expect(result.ok).toBe(true)
  })

  it('a signer that does not restamp is unaffected by the new guard', async () => {
    const participantSk = generateSecretKey()
    const identity = {
      pubkey: getPublicKey(participantSk),
      async signEvent(unsigned: { kind: number; created_at: number; tags: string[][]; content: string }): Promise<Event> {
        const { finalizeEvent } = await import('nostr-tools/pure')
        return finalizeEvent(unsigned, participantSk)
      },
    }
    const cred = await createDeviceCredential({
      identity,
      devicePubkey: getPublicKey(generateSecretKey()),
      scope: 'person',
      expiresAt: NOW + PERSON_CREDENTIAL_MAX_SECONDS,
      now: () => NOW,
    })
    const result = verifyDeviceCredential(cred, { identity: identity.pubkey, now: NOW })
    expect(result.ok).toBe(true)
  })

  it('a room credential is unaffected by the new guard even under a restamping signer (the guard is person-only)', async () => {
    const participantSk = generateSecretKey()
    const identity = restampingIdentity(participantSk, 10)
    const cred = await createDeviceCredential({
      identity,
      devicePubkey: getPublicKey(generateSecretKey()),
      roomId: 'a'.repeat(64),
      // Room credentials have no 30-day cap at all, so a margin far past it
      // still mints and verifies - the restamp cannot trip the person-only guard.
      expiresAt: NOW + PERSON_CREDENTIAL_MAX_SECONDS * 10,
      now: () => NOW,
    })
    const result = verifyDeviceCredential(cred, { roomId: 'a'.repeat(64), now: NOW })
    expect(result.ok).toBe(true)
  })

  it('a restamp that lands exactly on the cap (not over it) still mints', async () => {
    const participantSk = generateSecretKey()
    const identity = restampingIdentity(participantSk, 10)
    const cred = await createDeviceCredential({
      identity,
      devicePubkey: getPublicKey(generateSecretKey()),
      scope: 'person',
      expiresAt: NOW + PERSON_CREDENTIAL_MAX_SECONDS - 10,
      now: () => NOW,
    })
    expect(cred).toBeDefined()
    const result = verifyDeviceCredential(cred, { identity: identity.pubkey, now: NOW })
    expect(result.ok).toBe(true)
  })
})
