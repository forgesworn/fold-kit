import { describe, it, expect } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { createDeviceCredential, verifyDeviceCredential, PERSON_CREDENTIAL_MAX_SECONDS } from './credential.js'
import { localIdentity } from './identity.js'
import { KINDS } from './kinds.js'

const ROOM = 'a'.repeat(64)
const NOW = 1_800_000_000

function setup() {
  const participantSk = generateSecretKey()
  const deviceSk = generateSecretKey()
  return {
    participantSk,
    identity: localIdentity(participantSk),
    participant: getPublicKey(participantSk),
    device: getPublicKey(deviceSk),
  }
}

describe('device credentials', () => {
  it('accepts a credential signed by the participant for this room', async () => {
    const { participantSk, participant, device } = setup()
    const cred = await createDeviceCredential({
      identity: localIdentity(participantSk),
      devicePubkey: device,
      roomId: ROOM,
      expiresAt: NOW + 3600,
    })
    const result = verifyDeviceCredential(cred, { roomId: ROOM, now: NOW })
    expect(result).toEqual({ ok: true, participant, device })
  })

  it('remembers a good signature only for the identical credential', async () => {
    const { participantSk, participant, device } = setup()
    const cred = await createDeviceCredential({ identity: localIdentity(participantSk), devicePubkey: device, roomId: ROOM, expiresAt: NOW + 3600 })
    expect(verifyDeviceCredential(cred, { roomId: ROOM, now: NOW })).toEqual({ ok: true, participant, device })
    // Checked before: still refused once anything signed has changed.
    const moved = { ...cred, tags: cred.tags.map(t => t[0] === 'expiration' ? ['expiration', String(NOW + 7200)] : t) }
    expect(verifyDeviceCredential(moved, { roomId: ROOM, now: NOW })).toEqual({ ok: false, reason: 'bad signature' })
    expect(verifyDeviceCredential({ ...cred, sig: cred.sig.replace(/^./, c => c === '0' ? '1' : '0') }, { roomId: ROOM, now: NOW }).ok).toBe(false)
    // The same credential signed again carries a different, equally good signature.
    const again = finalizeEvent({ kind: cred.kind, created_at: cred.created_at, tags: cred.tags, content: cred.content }, participantSk)
    expect(again.id).toBe(cred.id)
    expect(again.sig).not.toBe(cred.sig)
    expect(verifyDeviceCredential(again, { roomId: ROOM, now: NOW })).toEqual({ ok: true, participant, device })
  })

  it('rejects a credential for a different room', async () => {
    const { participantSk, device } = setup()
    const cred = await createDeviceCredential({
      identity: localIdentity(participantSk),
      devicePubkey: device,
      roomId: ROOM,
      expiresAt: NOW + 3600,
    })
    const result = verifyDeviceCredential(cred, { roomId: 'b'.repeat(64), now: NOW })
    expect(result).toEqual({ ok: false, reason: 'wrong room' })
  })

  it('rejects an expired credential', async () => {
    const { participantSk, device } = setup()
    const cred = await createDeviceCredential({
      identity: localIdentity(participantSk),
      devicePubkey: device,
      roomId: ROOM,
      expiresAt: NOW - 1,
    })
    const result = verifyDeviceCredential(cred, { roomId: ROOM, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'expired' })
  })

  it('rejects a credential whose signature has been tampered with', async () => {
    const { participantSk, device } = setup()
    const cred = await createDeviceCredential({
      identity: localIdentity(participantSk),
      devicePubkey: device,
      roomId: ROOM,
      expiresAt: NOW + 3600,
    })
    const tampered = { ...cred, tags: [...cred.tags.map((t) => [...t])] }
    tampered.tags[1][1] = 'c'.repeat(64) // swap the delegated device
    const result = verifyDeviceCredential(tampered, { roomId: ROOM, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'bad signature' })
  })

  it('uses the NIP-40 expiration tag, never "expiry"', async () => {
    const { participantSk, device } = setup()
    const cred = await createDeviceCredential({
      identity: localIdentity(participantSk),
      devicePubkey: device,
      roomId: ROOM,
      expiresAt: NOW + 3600,
    })
    const names = cred.tags.map((t) => t[0])
    expect(names).toContain('expiration')
    expect(names).not.toContain('expiry')
  })

  it('rejects a credential with no expiration tag', async () => {
    const { participantSk, device } = setup()
    const cred = await createDeviceCredential({
      identity: localIdentity(participantSk),
      devicePubkey: device,
      roomId: ROOM,
      expiresAt: NOW + 3600,
    })
    const stripped = { ...cred, tags: cred.tags.filter((t) => t[0] !== 'expiration') }
    const result = verifyDeviceCredential(stripped, { roomId: ROOM, now: NOW })
    expect(result.ok).toBe(false)
  })

  it('rejects a credential whose expiration tag is not a number, rather than treating it as never expiring', async () => {
    const { participantSk, device } = setup()
    // Built (and genuinely signed) directly, rather than via
    // createDeviceCredential + post-hoc tampering: tampering the tag after
    // signing would fail on the signature check first and never reach the
    // expiry comparison this test exists to exercise.
    const cred = finalizeEvent(
      {
        kind: KINDS.CREDENTIAL,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['d', ROOM],
          ['device', device],
          // `Number('not-a-number')` is NaN, and every comparison with NaN
          // is false - so a naive `Number(expiration) <= now` treats this
          // as unexpired forever. That is a fail-open default in a
          // security check.
          ['expiration', 'not-a-number'],
        ],
        content: '',
      },
      participantSk,
    )
    const result = verifyDeviceCredential(cred, { roomId: ROOM, now: NOW })
    expect(result).toEqual({ ok: false, reason: 'no expiration' })
  })

  it('normalises the returned device to lower case, even when the credential names it in upper case', async () => {
    // The `device` tag is free text set by whoever minted the credential -
    // nothing forces lower case. Downstream (roster decode, secondary-device
    // adoption) compares this against a self-derived pubkey, which is always
    // canonical, so this must be too.
    const { participantSk, device } = setup()
    const cred = await createDeviceCredential({
      identity: localIdentity(participantSk),
      devicePubkey: device.toUpperCase(),
      roomId: ROOM,
      expiresAt: NOW + 3600,
    })
    const result = verifyDeviceCredential(cred, { roomId: ROOM, now: NOW })
    expect(result).toEqual({ ok: true, participant: expect.any(String), device })
  })
})

describe('person credentials', () => {
  it('a person credential verifies for the person, is refused as a room credential unless the room accepts people, and never for another person', async () => {
    const { participantSk, participant, device } = setup()
    const cred = await createDeviceCredential({ identity: localIdentity(participantSk), devicePubkey: device, scope: 'person', label: 'phone', expiresAt: NOW + 7 * 24 * 3600, now: () => NOW })
    expect(cred.tags).toContainEqual(['d', participant])
    expect(cred.tags).toContainEqual(['scope', 'person'])
    expect(verifyDeviceCredential(cred, { identity: participant, now: NOW })).toEqual({ ok: true, participant, device })
    expect(verifyDeviceCredential(cred, { roomId: ROOM, now: NOW })).toEqual({ ok: false, reason: 'person credential where a room credential was expected' })
    expect(verifyDeviceCredential(cred, { roomId: ROOM, now: NOW, acceptPerson: true })).toEqual({ ok: true, participant, device })
    expect(verifyDeviceCredential(cred, { identity: 'f'.repeat(64), now: NOW }).ok).toBe(false)
  })
  it('a room credential is never a person credential, and a room credential with a scope tag is refused', async () => {
    const { participantSk, participant, device } = setup()
    const room = await createDeviceCredential({ identity: localIdentity(participantSk), devicePubkey: device, roomId: ROOM, expiresAt: NOW + 3600, now: () => NOW })
    expect(verifyDeviceCredential(room, { identity: participant, now: NOW })).toEqual({ ok: false, reason: 'not a person credential' })
    const scoped = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags: [['d', ROOM], ['device', device], ['expiration', String(NOW + 3600)], ['scope', 'person']], content: '' }, participantSk)
    expect(verifyDeviceCredential(scoped, { roomId: ROOM, now: NOW }).ok).toBe(false)
  })
  it('a person credential may not run more than 30 days, at issue or at verification', async () => {
    const { participantSk, participant, device } = setup()
    await expect(createDeviceCredential({ identity: localIdentity(participantSk), devicePubkey: device, scope: 'person', expiresAt: NOW + PERSON_CREDENTIAL_MAX_SECONDS + 1, now: () => NOW })).rejects.toThrow(/30 days/)
    const long = finalizeEvent({ kind: KINDS.CREDENTIAL, created_at: NOW, tags: [['d', participant], ['device', device], ['expiration', String(NOW + PERSON_CREDENTIAL_MAX_SECONDS + 1)], ['scope', 'person']], content: '' }, participantSk)
    expect(verifyDeviceCredential(long, { identity: participant, now: NOW })).toEqual({ ok: false, reason: 'longer than 30 days' })
  })
  it('refuses a person credential that names a room, and a room credential that names none', async () => {
    const { participantSk, device } = setup()
    await expect(createDeviceCredential({ identity: localIdentity(participantSk), devicePubkey: device, scope: 'person', roomId: ROOM, expiresAt: NOW + 3600 })).rejects.toThrow(/names no room/)
    await expect(createDeviceCredential({ identity: localIdentity(participantSk), devicePubkey: device, expiresAt: NOW + 3600 })).rejects.toThrow(/needs a room/)
  })
})
