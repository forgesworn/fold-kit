import { describe, it, expect } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { evaluateAccess, issueKindredProof } from './access.js'

const NOW = 1_800_000_000
const ROOM = 'e'.repeat(64)

describe('access tiers', () => {
  it('admits anyone when the room is open', () => {
    const r = evaluateAccess({ tier: 'open' }, 'a'.repeat(64), undefined, NOW, ROOM)
    expect(r.admitted).toBe(true)
  })

  it('refuses an unproven participant when the room is kith-gated', () => {
    const r = evaluateAccess({ tier: 'kith' }, 'a'.repeat(64), undefined, NOW, ROOM)
    expect(r).toEqual({ admitted: false, reason: 'no kindred proof' })
  })

  it('admits a valid kith proof to a kith-gated room', () => {
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const proof = issueKindredProof({ hostSk, participant: guest, tier: 'kith', roomId: ROOM, expiresAt: NOW + 3600 })
    const r = evaluateAccess({ tier: 'kith', admitted: [getPublicKey(hostSk)] }, guest, proof, NOW, ROOM)
    expect(r.admitted).toBe(true)
  })

  it('admits a kin proof to a kith-gated room, because kin is closer than kith', () => {
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const proof = issueKindredProof({ hostSk, participant: guest, tier: 'kin', roomId: ROOM, expiresAt: NOW + 3600 })
    const r = evaluateAccess({ tier: 'kith', admitted: [getPublicKey(hostSk)] }, guest, proof, NOW, ROOM)
    expect(r.admitted).toBe(true)
  })

  it('refuses a ken proof to a kith-gated room, because ken is only one-way recognition', () => {
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const proof = issueKindredProof({ hostSk, participant: guest, tier: 'ken', roomId: ROOM, expiresAt: NOW + 3600 })
    const r = evaluateAccess({ tier: 'kith', admitted: [getPublicKey(hostSk)] }, guest, proof, NOW, ROOM)
    expect(r).toEqual({ admitted: false, reason: 'tier too low' })
  })

  it('refuses a proof issued by someone the room does not trust', () => {
    const strangerSk = generateSecretKey()
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const proof = issueKindredProof({ hostSk: strangerSk, participant: guest, tier: 'kith', roomId: ROOM, expiresAt: NOW + 3600 })
    const r = evaluateAccess({ tier: 'kith', admitted: [getPublicKey(hostSk)] }, guest, proof, NOW, ROOM)
    expect(r).toEqual({ admitted: false, reason: 'untrusted issuer' })
  })

  it('refuses a proof naming a different participant', () => {
    const hostSk = generateSecretKey()
    const proof = issueKindredProof({ hostSk, participant: 'b'.repeat(64), tier: 'kith', roomId: ROOM, expiresAt: NOW + 3600 })
    const r = evaluateAccess({ tier: 'kith', admitted: [getPublicKey(hostSk)] }, 'c'.repeat(64), proof, NOW, ROOM)
    expect(r).toEqual({ admitted: false, reason: 'proof names another participant' })
  })

  it('refuses an expired proof', () => {
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const proof = issueKindredProof({ hostSk, participant: guest, tier: 'kith', roomId: ROOM, expiresAt: NOW - 1 })
    const r = evaluateAccess({ tier: 'kith', admitted: [getPublicKey(hostSk)] }, guest, proof, NOW, ROOM)
    expect(r).toEqual({ admitted: false, reason: 'expired' })
  })

  it('refuses a proof whose signature has been tampered with', () => {
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const proof = issueKindredProof({ hostSk, participant: guest, tier: 'kith', roomId: ROOM, expiresAt: NOW + 3600 })
    const tampered = { ...proof, tier: 'kin' as const }
    const r = evaluateAccess({ tier: 'kith', admitted: [getPublicKey(hostSk)] }, guest, tampered, NOW, ROOM)
    expect(r).toEqual({ admitted: false, reason: 'bad signature' })
  })

  it('refuses a proof carrying a tier it does not recognise', () => {
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    // Genuinely SIGNED over the unknown tier, so nothing downstream catches
    // it: the tier comparison is the only thing standing in the way.
    // TIER_RANK[unknown] is undefined and `undefined < 2` is false, so the
    // "too low" branch is skipped and the proof sails through. A gate must
    // fail closed, whatever a trusted issuer chose to write in it.
    const nonsense = issueKindredProof({
      hostSk,
      participant: guest,
      tier: 'archon' as unknown as 'kith',
      roomId: ROOM,
      expiresAt: NOW + 3600,
    })
    const r = evaluateAccess({ tier: 'kith', admitted: [getPublicKey(hostSk)] }, guest, nonsense, NOW, ROOM)
    expect(r.admitted, 'an unrecognised tier was admitted to a kith gate').toBe(false)
  })

  it('matches the issuer allow-list whatever case the hex is stored in', () => {
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const proof = issueKindredProof({ hostSk, participant: guest, tier: 'kith', roomId: ROOM, expiresAt: NOW + 3600 })
    const upper = getPublicKey(hostSk).toUpperCase()
    const r = evaluateAccess({ tier: 'kith', admitted: [upper] }, guest, proof, NOW, ROOM)
    expect(r.admitted, 'an allow-list entry in upper-case hex rejected its own issuer').toBe(true)
  })

  it('BUG (M1): refuses a proof minted for a different room', () => {
    // Without a room in the signed message a proof is a bearer token good in
    // every room that trusts its issuer, until it expires. An issuer who
    // vouched for a guest at one moot has not vouched for them at every moot
    // the room's admitted list happens to name.
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const theirRoom = 'c'.repeat(64)
    const someoneElsesRoom = 'd'.repeat(64)
    const proof = issueKindredProof({ hostSk, participant: guest, tier: 'kith', roomId: theirRoom, expiresAt: NOW + 3600 })

    const policy = { tier: 'kith' as const, admitted: [getPublicKey(hostSk)] }
    expect(evaluateAccess(policy, guest, proof, NOW, theirRoom).admitted).toBe(true)
    expect(evaluateAccess(policy, guest, proof, NOW, someoneElsesRoom)).toEqual({
      admitted: false,
      reason: 'proof names another room',
    })
  })

  it('BUG (M1): binds the room into the signature, so it cannot simply be edited', () => {
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const theirRoom = 'c'.repeat(64)
    const someoneElsesRoom = 'd'.repeat(64)
    const proof = issueKindredProof({ hostSk, participant: guest, tier: 'kith', roomId: theirRoom, expiresAt: NOW + 3600 })

    const edited = { ...proof, room: someoneElsesRoom }
    const policy = { tier: 'kith' as const, admitted: [getPublicKey(hostSk)] }
    expect(evaluateAccess(policy, guest, edited, NOW, someoneElsesRoom)).toEqual({
      admitted: false,
      reason: 'bad signature',
    })
  })

  it('BUG (M1): gives every proof its own nonce, and binds that too', () => {
    // Two proofs with identical terms are otherwise the same bytes, so
    // there is nothing to tell one grant from another - or to revoke.
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const roomId = 'c'.repeat(64)
    const terms = { hostSk, participant: guest, tier: 'kith' as const, roomId, expiresAt: NOW + 3600 }

    const first = issueKindredProof(terms)
    const second = issueKindredProof(terms)
    expect(first.nonce).not.toBe(second.nonce)
    expect(first.nonce).toMatch(/^[0-9a-f]{64}$/)

    const policy = { tier: 'kith' as const, admitted: [getPublicKey(hostSk)] }
    expect(evaluateAccess(policy, guest, { ...first, nonce: second.nonce }, NOW, roomId)).toEqual({
      admitted: false,
      reason: 'bad signature',
    })
  })

  it('matches the room whatever case the hex is stored in', () => {
    const hostSk = generateSecretKey()
    const guest = 'b'.repeat(64)
    const roomId = 'c'.repeat(64)
    const proof = issueKindredProof({ hostSk, participant: guest, tier: 'kith', roomId, expiresAt: NOW + 3600 })

    const policy = { tier: 'kith' as const, admitted: [getPublicKey(hostSk)] }
    expect(evaluateAccess(policy, guest, proof, NOW, roomId.toUpperCase()).admitted).toBe(true)
  })
})

describe('members', () => {
  it('a members list shuts the door before any tier is considered', () => {
    const a = 'a'.repeat(64)
    const b = 'b'.repeat(64)
    expect(evaluateAccess({ tier: 'open', members: [a, b] }, a, undefined, NOW, ROOM).admitted).toBe(true)
    expect(evaluateAccess({ tier: 'open', members: [a, b] }, 'c'.repeat(64), undefined, NOW, ROOM)).toEqual({ admitted: false, reason: 'not a member' })
    // Case-insensitively, like every other identifier here.
    expect(evaluateAccess({ tier: 'open', members: [a.toUpperCase()] }, a, undefined, NOW, ROOM).admitted).toBe(true)
    // A member still needs the tier's proof when the room is gated.
    expect(evaluateAccess({ tier: 'kith', members: [a] }, a, undefined, NOW, ROOM)).toEqual({ admitted: false, reason: 'no kindred proof' })
  })
})
