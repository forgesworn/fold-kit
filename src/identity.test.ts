import { describe, it, expect } from 'vitest'
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure'
import type { SignetSigner } from 'signet-login'
import { localIdentity, type ParticipantIdentity } from './identity.js'
import { createDeviceCredential, verifyDeviceCredential } from './credential.js'
import { verifyEventUncached } from './verify.js'

const ROOM = 'a'.repeat(64)

/**
 * Stands in for signet-login's `SignetSigner`: a signer that lives somewhere
 * else - an extension, a bunker, a phone - and answers over a round trip.
 * Deliberately typed as `SignetSigner` rather than as `ParticipantIdentity`,
 * so this file fails to compile if the two shapes ever stop lining up.
 */
function remoteSigner(sk: Uint8Array, delayMs = 0): SignetSigner {
  return {
    pubkey: getPublicKey(sk),
    method: 'bunker',
    capabilities: { canSignEvents: true, hasNip44: true },
    async signEvent(template) {
      if (delayMs) await new Promise((resolve) => setTimeout(resolve, delayMs))
      return finalizeEvent(
        {
          kind: template.kind,
          created_at: template.created_at ?? Math.floor(Date.now() / 1000),
          tags: template.tags ?? [],
          content: template.content,
        },
        sk,
      )
    },
    async close() {},
  }
}

describe('localIdentity', () => {
  it('names the participant key it holds, and signs for it', async () => {
    const sk = generateSecretKey()
    const identity = localIdentity(sk)

    expect(identity.pubkey).toBe(getPublicKey(sk))

    const signed = await identity.signEvent({ kind: 1, created_at: 1, tags: [], content: 'hello' })
    expect(signed.pubkey).toBe(getPublicKey(sk))
    expect(verifyEventUncached(signed)).toBe(true)
  })

  it('normalises an upper-case pubkey a signer hands back', () => {
    const sk = generateSecretKey()
    expect(localIdentity(sk).pubkey).toBe(getPublicKey(sk).toLowerCase())
  })
})

describe('createDeviceCredential against an identity', () => {
  it('mints a credential a local key can verify', async () => {
    const sk = generateSecretKey()
    const device = getPublicKey(generateSecretKey())
    const cred = await createDeviceCredential({
      identity: localIdentity(sk),
      devicePubkey: device,
      roomId: ROOM,
      expiresAt: 2_000_000_000,
    })

    const verdict = verifyDeviceCredential(cred, { roomId: ROOM, now: 1_000_000_000 })
    expect(verdict).toEqual({ ok: true, participant: getPublicKey(sk), device })
  })

  it('mints the same credential through a signer that takes a round trip', async () => {
    const sk = generateSecretKey()
    const device = getPublicKey(generateSecretKey())
    // The whole point of the seam: this signer is asynchronous and the
    // credential path has to wait for it rather than block.
    const identity: ParticipantIdentity = remoteSigner(sk, 25)

    const cred = await createDeviceCredential({
      identity,
      devicePubkey: device,
      roomId: ROOM,
      expiresAt: 2_000_000_000,
    })

    const verdict = verifyDeviceCredential(cred, { roomId: ROOM, now: 1_000_000_000 })
    expect(verdict).toEqual({ ok: true, participant: getPublicKey(sk), device })
  })

  it('refuses a credential signed by a key other than the one the identity names', async () => {
    const claimed = generateSecretKey()
    const actual = generateSecretKey()
    const identity: ParticipantIdentity = {
      pubkey: getPublicKey(claimed),
      signEvent: async (unsigned) => finalizeEvent(unsigned, actual),
    }

    await expect(
      createDeviceCredential({
        identity,
        devicePubkey: getPublicKey(generateSecretKey()),
        roomId: ROOM,
        expiresAt: 2_000_000_000,
      }),
    ).rejects.toThrow(/signer/i)
  })

  it('refuses a credential whose terms the signer rewrote', async () => {
    const sk = generateSecretKey()
    const attacker = getPublicKey(generateSecretKey())
    const identity: ParticipantIdentity = {
      pubkey: getPublicKey(sk),
      // A signer that quietly authorises a different device than it was
      // asked to. The signature is genuine, so only comparing the terms
      // back catches it.
      signEvent: async (unsigned) =>
        finalizeEvent({ ...unsigned, tags: unsigned.tags.map((t) => (t[0] === 'device' ? ['device', attacker] : t)) }, sk),
    }

    await expect(
      createDeviceCredential({
        identity,
        devicePubkey: getPublicKey(generateSecretKey()),
        roomId: ROOM,
        expiresAt: 2_000_000_000,
      }),
    ).rejects.toThrow(/signer/i)
  })

  it('refuses an unsigned event dressed up as a credential', async () => {
    const sk = generateSecretKey()
    const identity: ParticipantIdentity = {
      pubkey: getPublicKey(sk),
      signEvent: async (unsigned) => ({
        ...unsigned,
        pubkey: getPublicKey(sk),
        id: '00'.repeat(32),
        sig: '00'.repeat(64),
      }),
    }

    await expect(
      createDeviceCredential({
        identity,
        devicePubkey: getPublicKey(generateSecretKey()),
        roomId: ROOM,
        expiresAt: 2_000_000_000,
      }),
    ).rejects.toThrow(/signer/i)
  })
})
