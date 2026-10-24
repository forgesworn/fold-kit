import { describe, it, expect } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { bytesToHex } from '@noble/hashes/utils'
import { parseRoomLink, encodeRoomLink } from './link.js'
import { createRoomInvitation, invitationAuthority } from './invitation.js'
import { encodeJoinUrl } from './room.js'

const BASE = 'https://example.test/j/'

describe('room links', () => {
  it('round-trips a version 2 invitation link with every hint the app writes', () => {
    const { invitation } = createRoomInvitation()
    const url = encodeRoomLink(BASE, {
      invitation,
      relays: ['wss://a.example', 'wss://b.example'],
      iceUrls: ['stun:stun.example:3478', 'turn:turn.example:3478'],
      policy: { tier: 'kith', admitted: ['AB'.repeat(32)] },
      pairingCode: new Uint8Array(16).fill(3),
    })
    const link = parseRoomLink(url)
    expect(link.invitation?.inviter).toBe(invitation.inviter)
    expect(bytesToHex(link.invitation!.bearer)).toBe(bytesToHex(invitation.bearer))
    expect(link.secret).toBeUndefined()
    expect(link.relays).toEqual(['wss://a.example', 'wss://b.example'])
    expect(link.iceUrls).toEqual(['stun:stun.example:3478', 'turn:turn.example:3478'])
    expect(link.policy).toEqual({ tier: 'kith', admitted: ['ab'.repeat(32)] })
    expect(bytesToHex(link.pairingCode!)).toBe('03'.repeat(16))
  })

  it('carries the room name when there is one, sanitised, and writes nothing when there is not', () => {
    const { invitation } = createRoomInvitation()
    const unnamed = encodeRoomLink(BASE, { invitation, relays: [], iceUrls: [] })
    expect(parseRoomLink(unnamed).name).toBeUndefined()
    expect(new TextDecoder().decode(base64urlnopad.decode(new URL(unnamed).hash.slice(1)))).not.toContain('"n"')

    const named = encodeRoomLink(BASE, { invitation, relays: [], iceUrls: [], name: '  Weekly\u200b town hall  ' })
    expect(parseRoomLink(named).name).toBe('Weekly town hall')

    // A name is text a stranger wrote: it gets the display-name treatment
    // on the way in whatever wrote the link.
    const hostile = base64urlnopad.encode(
      new TextEncoder().encode(JSON.stringify({ v: 2, j: base64urlnopad.encode(invitation.bearer), h: invitation.inviter, r: [], i: [], n: 'x'.repeat(100) })),
    )
    expect(parseRoomLink(`${BASE}#${hostile}`).name).toHaveLength(32)
    const notText = base64urlnopad.encode(
      new TextEncoder().encode(JSON.stringify({ v: 2, j: base64urlnopad.encode(invitation.bearer), h: invitation.inviter, r: [], i: [], n: 7 })),
    )
    expect(parseRoomLink(`${BASE}#${notText}`).name).toBeUndefined()
  })

  it('reads a legacy version 1 link the library itself wrote', () => {
    const secret = new Uint8Array(32).fill(5)
    const link = parseRoomLink(encodeJoinUrl(BASE, secret, ['wss://a.example']))
    expect(bytesToHex(link.secret!)).toBe('05'.repeat(32))
    expect(link.invitation).toBeUndefined()
    expect(link.relays).toEqual(['wss://a.example'])
    expect(link.iceUrls).toEqual([])
  })

  it('drops an ICE hint that is not a STUN or TURN url', () => {
    const { invitation } = createRoomInvitation()
    const url = encodeRoomLink(BASE, { invitation, relays: [], iceUrls: ['stun:ok.example', 'https://not-ice.example', 'javascript:alert(1)'] })
    expect(parseRoomLink(url).iceUrls).toEqual(['stun:ok.example'])
  })

  it('drops unsafe and duplicate relay hints', () => {
    const { invitation } = createRoomInvitation()
    const payload = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({
      v: 2, j: base64urlnopad.encode(invitation.bearer), h: invitation.inviter,
      r: ['https://not-a-relay.example', 'ws://public.example', 'wss://relay.example', 'wss://relay.example'], i: [],
    })))
    expect(parseRoomLink(`${BASE}#${payload}`).relays).toEqual(['wss://relay.example'])
  })

  it('refuses oversized fragments and hint arrays', () => {
    expect(() => parseRoomLink(`${BASE}#${'a'.repeat(16_385)}`)).toThrow(/too large/)
    const { invitation } = createRoomInvitation()
    const payload = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({
      v: 2, j: base64urlnopad.encode(invitation.bearer), h: invitation.inviter,
      r: Array.from({ length: 9 }, (_, i) => `wss://r${i}.example`), i: [],
    })))
    expect(() => parseRoomLink(`${BASE}#${payload}`)).toThrow(/too many relay/)
  })

  it('refuses a link whose admission rule it cannot read, rather than opening the room', () => {
    const payload = base64urlnopad.encode(
      new TextEncoder().encode(JSON.stringify({ v: 2, j: base64urlnopad.encode(new Uint8Array(32)), h: 'ab'.repeat(32), r: [], i: [], a: { tier: 'vip' } })),
    )
    expect(() => parseRoomLink(`${BASE}#${payload}`)).toThrow(/tier/)
  })

  it('refuses a link with no fragment, a fragment that is not base64, and one with neither invitation nor secret', () => {
    expect(() => parseRoomLink(BASE)).toThrow(/fragment/)
    expect(() => parseRoomLink(`${BASE}#not*base64`)).toThrow(/not valid/)
    const empty = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({ r: [] })))
    expect(() => parseRoomLink(`${BASE}#${empty}`)).toThrow(/neither/)
  })

  it('refuses a malformed version 2 invitation', () => {
    const payload = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({ v: 2, j: 'x', r: [] })))
    expect(() => parseRoomLink(`${BASE}#${payload}`)).toThrow(/invitation/)
  })
})

describe("a member's link naming the room's authority (version 5)", () => {
  const AUTHORITY = 'AB'.repeat(32)
  const fragment = (url: string) => JSON.parse(new TextDecoder().decode(base64urlnopad.decode(url.split('#')[1]!))) as Record<string, unknown>
  const link = (payload: Record<string, unknown>) => `${BASE}#${base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(payload)))}`

  it('round-trips the authority beside the inviter, lower-cased, and the inviter still answers', () => {
    const { invitation } = createRoomInvitation()
    const url = encodeRoomLink(BASE, { invitation: { ...invitation, authority: AUTHORITY }, relays: ['wss://a.example'], iceUrls: [] })
    expect(fragment(url)).toMatchObject({ v: 5, h: invitation.inviter, o: AUTHORITY.toLowerCase() })
    expect(Object.keys(fragment(url))).toEqual(['v', 'j', 'h', 'o', 'r', 'i'])
    const read = parseRoomLink(url)
    expect(read.invitation?.inviter).toBe(invitation.inviter)
    expect(read.invitation?.authority).toBe(AUTHORITY.toLowerCase())
    expect(read.invitation?.persistent).toBeUndefined()
    expect(bytesToHex(read.invitation!.bearer)).toBe(bytesToHex(invitation.bearer))
    expect(invitationAuthority(read.invitation!)).toBe(AUTHORITY.toLowerCase())
  })

  it('writes a link whose inviter is the authority exactly as before: version 2 or 3, no o', () => {
    for (const persistent of [false, true]) {
      const { invitation } = createRoomInvitation(persistent)
      const plain = encodeRoomLink(BASE, { invitation, relays: [], iceUrls: [] })
      expect(encodeRoomLink(BASE, { invitation: { ...invitation, authority: invitation.inviter.toUpperCase() }, relays: [], iceUrls: [] })).toBe(plain)
      expect(fragment(plain)).not.toHaveProperty('o')
      expect(fragment(plain).v).toBe(persistent ? 3 : 2)
      const read = parseRoomLink(plain)
      expect(read.invitation?.authority).toBeUndefined()
      expect(invitationAuthority(read.invitation!)).toBe(invitation.inviter)
    }
  })

  it('refuses to write a group link that names another authority, or a malformed one', () => {
    const group = createRoomInvitation(true).invitation
    expect(() => encodeRoomLink(BASE, { invitation: { ...group, authority: AUTHORITY }, relays: [], iceUrls: [] })).toThrow(/group link/)
    const meeting = createRoomInvitation().invitation
    expect(() => encodeRoomLink(BASE, { invitation: { ...meeting, authority: 'not hex' }, relays: [], iceUrls: [] })).toThrow(/32-byte hex/)
  })

  it('refuses a version 5 link with no authority, a malformed one, or one equal to its inviter', () => {
    const { invitation } = createRoomInvitation()
    const base = { v: 5, j: base64urlnopad.encode(invitation.bearer), h: invitation.inviter, r: [], i: [] }
    for (const o of [undefined, 42, 'zz'.repeat(32), 'ab'.repeat(31), invitation.inviter, invitation.inviter.toUpperCase()]) {
      expect(() => parseRoomLink(link({ ...base, o }))).toThrow(/malformed invitation/)
    }
    expect(parseRoomLink(link({ ...base, o: AUTHORITY })).invitation?.authority).toBe(AUTHORITY.toLowerCase())
  })

  it('ignores o on a version 2 link: only version 5 names an authority', () => {
    const { invitation } = createRoomInvitation()
    const read = parseRoomLink(link({ v: 2, j: base64urlnopad.encode(invitation.bearer), h: invitation.inviter, o: AUTHORITY, r: [], i: [] }))
    expect(read.invitation?.authority).toBeUndefined()
  })

  it('still refuses a version it does not know', () => {
    const { invitation } = createRoomInvitation()
    expect(() => parseRoomLink(link({ v: 6, j: base64urlnopad.encode(invitation.bearer), h: invitation.inviter, o: AUTHORITY, r: [] }))).toThrow(/unsupported version/)
  })
})
