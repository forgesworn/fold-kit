import { describe, it, expect } from 'vitest'
import { generateSecretKey, getPublicKey, finalizeEvent, type Event } from 'nostr-tools/pure'
import { createSubKeyCertificate, verifySubKeyCertificate, SUB_KEY_CERTIFICATE_SCOPE } from './sub-cert.js'
import { createDeviceCredential } from './credential.js'
import { localIdentity } from './identity.js'
import { KINDS } from './kinds.js'

const NOW = 1_800_000_000
const SIGNER_ID = 'a'.repeat(64)
const SUB_KEY = 'b'.repeat(64)

function setup() {
  const deviceSk = generateSecretKey()
  const subKeySk = generateSecretKey()
  return {
    deviceSk,
    identity: localIdentity(deviceSk),
    device: getPublicKey(deviceSk),
    subKeyPubkey: getPublicKey(subKeySk),
  }
}

/** A real, verified device credential naming `device`, with `expiration`
 *  equal to `expiresAt` - what a caller is expected to already hold before
 *  calling `verifySubKeyCertificate`. */
async function makeCredential(device: string, expiresAt: number): Promise<Event> {
  const participantSk = generateSecretKey()
  return createDeviceCredential({
    identity: localIdentity(participantSk),
    devicePubkey: device,
    scope: 'person',
    expiresAt,
    now: () => NOW,
  })
}

describe('sub-key certificates', () => {
  it('mints a certificate a matching verify call accepts', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({
      identity,
      signerId: SIGNER_ID,
      subKeyPubkey,
      expiresAt: NOW + 3600,
      now: () => NOW,
    })
    expect(cert.tags).toEqual([
      ['d', SIGNER_ID],
      ['device', subKeyPubkey],
      ['expiration', String(NOW + 3600)],
      ['scope', SUB_KEY_CERTIFICATE_SCOPE],
    ])
    expect(cert.content).toBe('')
    const credential = await makeCredential(device, NOW + 3600)
    const result = verifySubKeyCertificate(cert, {
      signerId: SIGNER_ID,
      credential,
      subKeyPubkey,
      now: NOW,
    })
    expect(result).toEqual({ ok: true, device, subKeyPubkey })
  })

  it('accepts a certificate signed after the message when no `at` bound is given', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result.ok).toBe(true)
  })

  it('accepts a certificate minted at or before the message time plus skew', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const result = verifySubKeyCertificate(cert, {
      signerId: SIGNER_ID,
      credential,
      subKeyPubkey,
      now: NOW,
      at: NOW - 100,
      skewSeconds: 300,
    })
    expect(result.ok).toBe(true)
  })

  it('accepts uppercase hex in the certificate\'s own tags (case-insensitive hex compare)', async () => {
    const { device, subKeyPubkey, deviceSk } = setup()
    const credential = await makeCredential(device, NOW + 3600)
    const upperTags = [
      ['d', SIGNER_ID.toUpperCase()],
      ['device', subKeyPubkey.toUpperCase()],
      ['expiration', String(NOW + 3600)],
      ['scope', 'sub'],
    ]
    const cert = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags: upperTags, content: '' }, deviceSk)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result.ok).toBe(true)
  })

  // --- Refusals (mutation-tested: each one is a security-relevant check) ---

  it('refuses a certificate for another signer id (wrong scope/board+epoch)', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const result = verifySubKeyCertificate(cert, { signerId: 'c'.repeat(64), credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong signer' })
  })

  it('refuses expiration unequal to the credential\'s', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 7200)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'expiration does not match the credential' })
  })

  it('refuses an expiration that is numerically equal but not the exact same string as the credential\'s', async () => {
    const { device, subKeyPubkey, deviceSk } = setup()
    const credential = await makeCredential(device, NOW + 3600)
    // The credential's own expiration tag is String(NOW + 3600); this
    // certificate spells the same number with a leading zero.
    const tags = [
      ['d', SIGNER_ID],
      ['device', subKeyPubkey],
      ['expiration', '0' + String(NOW + 3600)],
      ['scope', 'sub'],
    ]
    const cert = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags, content: '' }, deviceSk)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'non-canonical expiration' })
  })

  it('refuses a missing tag', async () => {
    // Tag-shape checks run before the signature is checked, so a naively
    // truncated (and therefore no-longer-validly-signed) copy is still
    // refused for the right reason: 'wrong tag count', not 'bad signature'.
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const missing = { ...cert, tags: cert.tags.slice(0, 3) }
    const result = verifySubKeyCertificate(missing, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong tag count' })
  })

  it('refuses an extra tag', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const extra = { ...cert, tags: [...cert.tags, ['extra', 'x']] }
    const result = verifySubKeyCertificate(extra, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong tag count' })
  })

  it('refuses a tag with an extra element', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const extraElement = { ...cert, tags: [[...cert.tags[0]!, 'z'], cert.tags[1]!, cert.tags[2]!, cert.tags[3]!] }
    const result = verifySubKeyCertificate(extraElement, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong tag shape' })
  })

  it('refuses non-empty content', async () => {
    const { identity, device, subKeyPubkey, deviceSk } = setup()
    const credential = await makeCredential(device, NOW + 3600)
    const tags = [
      ['d', SIGNER_ID],
      ['device', subKeyPubkey],
      ['expiration', String(NOW + 3600)],
      ['scope', 'sub'],
    ]
    const cert = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags, content: 'hello' }, deviceSk)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'non-empty content' })
    void identity
  })

  it('refuses tags out of order', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const reordered = { ...cert, tags: [cert.tags[1]!, cert.tags[0]!, cert.tags[2]!, cert.tags[3]!] }
    const result = verifySubKeyCertificate(reordered, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a renamed `d` tag at the correct position (not merely reordered)', async () => {
    const { device, subKeyPubkey, deviceSk } = setup()
    const credential = await makeCredential(device, NOW + 3600)
    const tags = [
      ['x', SIGNER_ID],
      ['device', subKeyPubkey],
      ['expiration', String(NOW + 3600)],
      ['scope', 'sub'],
    ]
    const cert = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags, content: '' }, deviceSk)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a renamed `expiration` tag at the correct position (not merely reordered)', async () => {
    const { device, subKeyPubkey, deviceSk } = setup()
    const credential = await makeCredential(device, NOW + 3600)
    const tags = [
      ['d', SIGNER_ID],
      ['device', subKeyPubkey],
      ['x', String(NOW + 3600)],
      ['scope', 'sub'],
    ]
    const cert = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags, content: '' }, deviceSk)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a renamed `device` tag at the correct position (not merely reordered)', async () => {
    const { device, subKeyPubkey, deviceSk } = setup()
    const credential = await makeCredential(device, NOW + 3600)
    const tags = [
      ['d', SIGNER_ID],
      ['x', subKeyPubkey],
      ['expiration', String(NOW + 3600)],
      ['scope', 'sub'],
    ]
    const cert = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags, content: '' }, deviceSk)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a renamed `scope` tag at the correct position (not merely reordered)', async () => {
    const { device, subKeyPubkey, deviceSk } = setup()
    const credential = await makeCredential(device, NOW + 3600)
    const tags = [
      ['d', SIGNER_ID],
      ['device', subKeyPubkey],
      ['expiration', String(NOW + 3600)],
      ['x', 'sub'],
    ]
    const cert = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags, content: '' }, deviceSk)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong tag order' })
  })

  it('refuses a scope other than "sub"', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const wrongScope = { ...cert, tags: [cert.tags[0]!, cert.tags[1]!, cert.tags[2]!, ['scope', 'person']] }
    const result = verifySubKeyCertificate(wrongScope, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong scope' })
  })

  it('refuses when the device tag does not equal the message signer (`event.pubkey`)', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey: 'e'.repeat(64), now: NOW })
    expect(result).toEqual({ ok: false, reason: 'device tag does not match the message signer' })
  })

  it('refuses when the certificate is not signed by the credential\'s device', async () => {
    const { identity, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const otherDevice = getPublicKey(generateSecretKey())
    const credential = await makeCredential(otherDevice, NOW + 3600)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong device' })
  })

  it('refuses a credential missing its device tag', async () => {
    const { identity, device, subKeyPubkey, deviceSk } = setup()
    void device
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const badCredential = finalizeEvent(
      { kind: KINDS.CREDENTIAL, created_at: NOW, tags: [['d', 'x'.repeat(64)], ['expiration', String(NOW + 3600)]], content: '' },
      generateSecretKey(),
    )
    void deviceSk
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential: badCredential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'credential missing device tag' })
  })

  it('refuses a credential missing its expiration tag', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const badCredential = finalizeEvent(
      { kind: KINDS.CREDENTIAL, created_at: NOW, tags: [['d', 'x'.repeat(64)], ['device', device]], content: '' },
      generateSecretKey(),
    )
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential: badCredential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'credential missing expiration tag' })
  })

  it('refuses an expired certificate', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW + 3601 })
    expect(result).toEqual({ ok: false, reason: 'expired' })
  })

  it('refuses a non-canonical expiration', async () => {
    const { device, subKeyPubkey, deviceSk } = setup()
    const credential = await makeCredential(device, NOW + 3600)
    const tags = [
      ['d', SIGNER_ID],
      ['device', subKeyPubkey],
      ['expiration', 'soon'],
      ['scope', 'sub'],
    ]
    const cert = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags, content: '' }, deviceSk)
    const result = verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'non-canonical expiration' })
  })

  it('refuses a certificate minted after the message it rode in on, once an `at`/skew bound is given', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const result = verifySubKeyCertificate(cert, {
      signerId: SIGNER_ID,
      credential,
      subKeyPubkey,
      now: NOW,
      at: NOW - 301,
      skewSeconds: 300,
    })
    expect(result).toEqual({ ok: false, reason: 'certificate minted after the message it rode in on' })
  })

  it('refuses a bad signature', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const tampered = { ...cert, sig: cert.sig.replace(/^./, (c) => (c === '0' ? '1' : '0')) }
    const result = verifySubKeyCertificate(tampered, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'bad signature' })
  })

  it('refuses the wrong kind', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    const wrongKind = { ...cert, kind: KINDS.CHAT }
    const result = verifySubKeyCertificate(wrongKind, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong kind' })
  })

  it('caches a verified signature for the identical certificate, but not for a mutated copy under the same id', async () => {
    const { identity, device, subKeyPubkey } = setup()
    const cert = await createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW })
    const credential = await makeCredential(device, NOW + 3600)
    expect(verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW }).ok).toBe(true)
    expect(verifySubKeyCertificate(cert, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW }).ok).toBe(true)
    const tampered = { ...cert, sig: cert.sig.replace(/^./, (c) => (c === '0' ? '1' : '0')) }
    expect(verifySubKeyCertificate(tampered, { signerId: SIGNER_ID, credential, subKeyPubkey, now: NOW }).ok).toBe(false)
  })

  // --- Mint-time input validation (nit: item 6) ---

  it('mint refuses a non-hex signerId', async () => {
    const { identity, subKeyPubkey } = setup()
    await expect(
      createSubKeyCertificate({ identity, signerId: 'not-hex', subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW }),
    ).rejects.toThrow(/signerId/)
  })

  it('mint refuses a non-hex subKeyPubkey', async () => {
    const { identity } = setup()
    await expect(
      createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey: 'zz', expiresAt: NOW + 3600, now: () => NOW }),
    ).rejects.toThrow(/subKeyPubkey/)
  })

  it('mint refuses a non-integer expiresAt', async () => {
    const { identity, subKeyPubkey } = setup()
    await expect(
      createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: 1.5, now: () => NOW }),
    ).rejects.toThrow(/expiresAt/)
  })

  it('mint refuses an expiresAt that is not in the future', async () => {
    const { identity, subKeyPubkey } = setup()
    await expect(
      createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW, now: () => NOW }),
    ).rejects.toThrow(/expiresAt/)
    await expect(
      createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW - 1, now: () => NOW }),
    ).rejects.toThrow(/expiresAt/)
  })

  it('mint refuses a signer that returns a certificate for different terms', async () => {
    const deviceSk = generateSecretKey()
    const device = getPublicKey(deviceSk)
    const subKeyPubkey = getPublicKey(generateSecretKey())
    const identity = {
      pubkey: device,
      async signEvent(unsigned: { kind: number; created_at: number; tags: string[][]; content: string }) {
        return finalizeEvent({ ...unsigned, tags: [...unsigned.tags, ['extra', 'x']] }, deviceSk)
      },
    }
    await expect(
      createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW }),
    ).rejects.toThrow(/different terms/)
  })

  it('mint refuses a signer that returns a different kind', async () => {
    const deviceSk = generateSecretKey()
    const device = getPublicKey(deviceSk)
    const subKeyPubkey = getPublicKey(generateSecretKey())
    const identity = {
      pubkey: device,
      async signEvent(unsigned: { kind: number; created_at: number; tags: string[][]; content: string }) {
        return finalizeEvent({ ...unsigned, kind: unsigned.kind + 1 }, deviceSk)
      },
    }
    await expect(
      createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW }),
    ).rejects.toThrow(/something else/)
  })

  it('mint refuses a signer that returns different content', async () => {
    const deviceSk = generateSecretKey()
    const device = getPublicKey(deviceSk)
    const subKeyPubkey = getPublicKey(generateSecretKey())
    const identity = {
      pubkey: device,
      async signEvent(unsigned: { kind: number; created_at: number; tags: string[][]; content: string }) {
        return finalizeEvent({ ...unsigned, content: 'not empty' }, deviceSk)
      },
    }
    await expect(
      createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW }),
    ).rejects.toThrow(/something else/)
  })

  it('mint refuses a signer that signs with a different key', async () => {
    const deviceSk = generateSecretKey()
    const otherSk = generateSecretKey()
    const device = getPublicKey(deviceSk)
    const subKeyPubkey = getPublicKey(generateSecretKey())
    const identity = {
      pubkey: device,
      async signEvent(unsigned: { kind: number; created_at: number; tags: string[][]; content: string }) {
        return finalizeEvent(unsigned, otherSk)
      },
    }
    await expect(
      createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW }),
    ).rejects.toThrow(/different key/)
  })

  it('mint refuses a signer that returns an invalid signature (id/pubkey/tags/content all match)', async () => {
    const deviceSk = generateSecretKey()
    const device = getPublicKey(deviceSk)
    const subKeyPubkey = getPublicKey(generateSecretKey())
    const identity = {
      pubkey: device,
      async signEvent(unsigned: { kind: number; created_at: number; tags: string[][]; content: string }) {
        const real = finalizeEvent(unsigned, deviceSk)
        // Flip a bit in the signature only - id/pubkey/kind/tags/content are
        // all exactly what was asked for, so only the final verifyEventUncached
        // check (not any of the earlier equality checks) can catch this.
        const badSig = real.sig.replace(/^./, (c) => (c === '0' ? '1' : '0'))
        return { ...real, sig: badSig }
      },
    }
    await expect(
      createSubKeyCertificate({ identity, signerId: SIGNER_ID, subKeyPubkey, expiresAt: NOW + 3600, now: () => NOW }),
    ).rejects.toThrow(/does not verify/)
  })
})
