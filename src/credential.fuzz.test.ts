import { describe, it, expect } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { createDeviceCredential, verifyDeviceCredential } from './credential.js'
import { localIdentity } from './identity.js'
import { KINDS } from './kinds.js'

// A seeded generator so a failure reproduces from its seed.
function rng(seed: number) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 0x100000000 } }
function flip(s: string, r: () => number): string { const i = Math.floor(r() * s.length); return s.slice(0, i) + String.fromCharCode(s.charCodeAt(i) ^ (1 << Math.floor(r() * 6))) + s.slice(i + 1) }
const ROOM = 'a'.repeat(64)
const NOW = 1_800_000_000
const N = 600

describe('fuzz: device credentials', () => {
  it('a mutated room or person credential is accepted only when it changes nothing', async () => {
    const r = rng(41)
    const sk = generateSecretKey()
    const device = getPublicKey(generateSecretKey())
    const room = await createDeviceCredential({ identity: localIdentity(sk), devicePubkey: device, roomId: ROOM, expiresAt: NOW + 3600, now: () => NOW })
    const person = await createDeviceCredential({ identity: localIdentity(sk), devicePubkey: device, scope: 'person', expiresAt: NOW + 3600, now: () => NOW })
    const canonRoom = JSON.stringify(verifyDeviceCredential(room, { roomId: ROOM, now: NOW }))
    const canonPerson = JSON.stringify(verifyDeviceCredential(person, { identity: getPublicKey(sk), now: NOW }))
    let accepted = 0
    for (let i = 0; i < N; i++) {
      const src = r() < 0.5 ? room : person
      const m = { ...src, tags: src.tags.map((t) => [...t]) }
      const op = Math.floor(r() * 6)
      if (op === 0) m.sig = flip(m.sig, r)
      else if (op === 1) m.pubkey = flip(m.pubkey, r)
      else if (op === 2) { const t = m.tags[Math.floor(r() * m.tags.length)]!; t[1] = flip(t[1] ?? '', r) }
      else if (op === 3) m.tags = m.tags.filter((_, j) => j !== Math.floor(r() * m.tags.length))
      else if (op === 4) m.tags.push(['scope', r() < 0.5 ? 'person' : 'other'])
      else m.kind = Math.floor(r() * 40000)
      let out: string | undefined
      const asRoom = verifyDeviceCredential(m, { roomId: ROOM, now: NOW, acceptPerson: true })
      const asPerson = verifyDeviceCredential(m, { identity: getPublicKey(sk), now: NOW })
      if (asRoom.ok) out = JSON.stringify(asRoom)
      if (asPerson.ok) out = JSON.stringify(asPerson)
      if (out !== undefined) {
        accepted++
        // Only a hex-case flip inside an already lower-cased field survives, and the verdict is unchanged.
        expect([canonRoom, canonPerson]).toContain(out)
        expect(JSON.stringify(m).toLowerCase()).toBe(JSON.stringify(src).toLowerCase())
      }
    }
    expect(accepted).toBeLessThan(N / 3)
  })
  it('garbage never verifies and never throws', () => {
    const r = rng(42)
    for (let i = 0; i < 300; i++) {
      const junk = finalizeEvent({ kind: r() < 0.5 ? KINDS.CREDENTIAL : Math.floor(r() * 40000), created_at: NOW, tags: [['d', r() < 0.5 ? ROOM : 'zz'], ['expiration', r() < 0.5 ? String(NOW + 10) : 'soon'], ['device', 'q'.repeat(Math.floor(r() * 70))]], content: 'x'.repeat(Math.floor(r() * 100)) }, generateSecretKey())
      expect(() => verifyDeviceCredential(junk, { roomId: ROOM, now: NOW })).not.toThrow()
      expect(() => verifyDeviceCredential(junk, { identity: junk.pubkey, now: NOW })).not.toThrow()
      expect(verifyDeviceCredential(junk, { identity: junk.pubkey, now: NOW }).ok).toBe(false)
    }
  })
})
