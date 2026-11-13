import { describe, expect, it } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure'
import { signNodeRoom, readNodeRoom, encodeNodeRoomLink, encodeShortNodeRoomLink, parseNodeRoomLink, longNodeRoomLink, inspectNodeRoomLink,
  SHORT_NODE_LINK_VERSION } from './node-room.js'
import { deriveRoom } from './room.js'
import { parseRoomLink } from './link.js'

const now = 1_900_000_000, base = 'https://kithmoot.app/j/'
const authority = generateSecretKey(), room = deriveRoom(generateSecretKey()).roomId, serviceKey = getPublicKey(generateSecretKey())
const sign = (extra: Partial<Parameters<typeof signNodeRoom>[0]> = {}) =>
  signNodeRoom({ authoritySk: authority, room, serviceKey, origin: 'https://demo.forgesworn.dev', now, ...extra })
const policy = { tier: 'open' as const, members: [getPublicKey(generateSecretKey()), getPublicKey(generateSecretKey())], quiet: true as const }
const records = {
  plain: sign(),
  ends: sign({ endsAt: now + 86400 }),
  ports: sign({ turnPorts: { udpTcp: 34790, tls: 53499 } }),
  existing: sign({ existing: { destruct: false } }),
  destruct: sign({ existing: { destruct: true }, endsAt: now + 3600 }),
  everything: sign({ existing: { destruct: true, policy }, endsAt: now + 30 * 86400, turnPorts: { udpTcp: 34790, tls: 53499 } }),
}
const fragment = (link: string) => base64urlnopad.decode(new URL(link).hash.slice(1))
const withFragment = (link: string, bytes: Uint8Array) => `${link.slice(0, link.indexOf('#'))}#${base64urlnopad.encode(bytes)}`

describe('short node-room links', () => {
  it.each(Object.entries(records))('rebuilds the identical signed %s record from a version 7 link', (_, event) => {
    const short = encodeShortNodeRoomLink(base, event, now), long = encodeNodeRoomLink(base, event, now)
    expect(fragment(short)[0]).toBe(SHORT_NODE_LINK_VERSION)
    expect(parseNodeRoomLink(short, now)).toEqual(readNodeRoom(event, now))
    expect(parseNodeRoomLink(short, now)!.event.id).toBe(event.id)
    expect(short.length).toBeLessThan(long.length / 2)
  })
  it('keeps a plain room link under 300 characters', () => {
    expect(encodeShortNodeRoomLink(base, records.plain, now).length).toBeLessThan(300)
    expect(encodeShortNodeRoomLink(base, records.ends, now).length).toBeLessThan(300)
  })
  it('is refused by the legacy parser instead of being read as a bearer invitation', () => {
    for (const event of Object.values(records)) expect(() => parseRoomLink(encodeShortNodeRoomLink(base, event, now))).toThrow('not valid')
  })
  it('refuses every single-bit change, a truncation and a trailing byte', () => {
    const link = encodeShortNodeRoomLink(base, records.everything, now), bytes = fragment(link)
    for (let i = 0; i < bytes.length; i++) {
      const changed = bytes.slice(); changed[i]! ^= 1
      // inspect gives null only when parseNodeRoomLink does too, and no ended or early state either
      expect(inspectNodeRoomLink(withFragment(link, changed), now), `byte ${i}`).toBeNull()
    }
    expect(parseNodeRoomLink(withFragment(link, bytes.slice(0, -1)), now)).toBeNull()
    expect(parseNodeRoomLink(withFragment(link, Uint8Array.of(...bytes, 0)), now)).toBeNull()
  }, 30_000)
  it('refuses unknown flags and existing-room flags on a new-room record', () => {
    const bytes = fragment(encodeShortNodeRoomLink(base, records.plain, now))
    for (const flag of [8, 16, 32, 128]) {
      const changed = bytes.slice(); changed[1]! |= flag
      expect(parseNodeRoomLink(withFragment(base + '#x', changed), now)).toBeNull()
    }
  })
  it('keeps the long link for a record signed with other JSON spelling', () => {
    const body = JSON.parse(records.plain.content) as Record<string, unknown>, { v, ...rest } = body
    const reordered = finalizeEvent({ kind: records.plain.kind, created_at: now, tags: records.plain.tags, content: JSON.stringify({ ...rest, v }) }, authority)
    expect(readNodeRoom(reordered, now)).not.toBeNull()
    expect(encodeShortNodeRoomLink(base, reordered, now)).toBe(encodeNodeRoomLink(base, reordered, now))
  })
  it('opens a short link on any base and only lengthens an https one', () => {
    const fragment = new URL(encodeShortNodeRoomLink(base, records.ends, now)).hash
    const tracked = `https://kithmoot.app/j/?fbclid=abc${fragment}`
    expect(parseNodeRoomLink(tracked, now)!.event.id).toBe(records.ends.id)
    expect(longNodeRoomLink(tracked, now)).toBe(encodeNodeRoomLink('https://kithmoot.app/j/?fbclid=abc', records.ends, now))
    for (const other of [`kithmoot://join${fragment}`, `http://localhost:5173/j/${fragment}`]) {
      expect(parseNodeRoomLink(other, now)!.event.id).toBe(records.ends.id)
      expect(longNodeRoomLink(other, now)).toBeNull()
      expect(inspectNodeRoomLink(other, now)?.state).toBe('open')
    }
  })
  it('turns a short link into the long form for storage and leaves a long link alone', () => {
    const short = encodeShortNodeRoomLink(base, records.everything, now), long = encodeNodeRoomLink(base, records.everything, now)
    const stored = longNodeRoomLink(short, now)!
    expect(fragment(stored)[0]).not.toBe(SHORT_NODE_LINK_VERSION)
    expect(parseNodeRoomLink(stored, now)).toEqual(parseNodeRoomLink(short, now))
    expect(longNodeRoomLink(long, now)).toBe(long)
    expect(longNodeRoomLink(short, now + 31 * 86400)).toBeNull()
    expect(longNodeRoomLink(base + '#AAAA', now)).toBeNull()
  })
})

describe('inspecting a node-room link', () => {
  it.each([['short', encodeShortNodeRoomLink], ['long', encodeNodeRoomLink]] as const)('tells an ended or early %s link from a broken one', (_, encode) => {
    const link = encode(base, records.ends, now), endsAt = now + 86400
    expect(inspectNodeRoomLink(link, now)).toEqual({ state: 'open', node: readNodeRoom(records.ends, now) })
    expect(inspectNodeRoomLink(link, endsAt - 1)?.state).toBe('open')
    expect(inspectNodeRoomLink(link, endsAt)).toEqual({ state: 'ended', endsAt })
    expect(inspectNodeRoomLink(link, endsAt + 86400 * 365)).toEqual({ state: 'ended', endsAt })
    expect(inspectNodeRoomLink(link, now - 30)?.state).toBe('open')
    expect(inspectNodeRoomLink(link, now - 31)).toEqual({ state: 'early', createdAt: now })
  })
  it('gives no state for a forged, unparseable or legacy link', () => {
    const forged = finalizeEvent({ kind: records.ends.kind, created_at: now, tags: records.ends.tags, content: records.ends.content }, generateSecretKey())
    const tampered = { ...forged, pubkey: records.ends.pubkey }
    expect(inspectNodeRoomLink(`${base}#${base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({ v: 6, node: tampered })))}`, now + 86400)).toBeNull()
    expect(inspectNodeRoomLink(base + '#', now)).toBeNull()
    expect(inspectNodeRoomLink(base + '#AAAA', now)).toBeNull()
    expect(inspectNodeRoomLink(`${base}#${base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({ v: 2, j: 'x', h: 'y' })))}`, now)).toBeNull()
    expect(inspectNodeRoomLink('not a url', now)).toBeNull()
  })
  it('keeps a record with no end open, as readNodeRoom does', () => {
    const link = encodeShortNodeRoomLink(base, records.plain, now)
    expect(inspectNodeRoomLink(link, now + 10 * 365 * 86400)).toEqual({ state: 'open', node: readNodeRoom(records.plain, now + 10 * 365 * 86400) })
  })
})
