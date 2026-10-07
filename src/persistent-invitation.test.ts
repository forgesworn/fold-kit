import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/pure'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { createRoomInvitation, decodeInvitationRetirementNotice, deriveInvitationId, encodeInvitationRetirement, ROOM_ENDED_MESSAGE } from './invitation.js'
import { KINDS } from './kinds.js'
import { encodePersistentInvitation, decodePersistentInvitation, requestPersistentRoomAdmission } from './persistent-invitation.js'
import { deriveRoom, generateRoomSecret } from './room.js'
import { encodeRoomLink, parseRoomLink } from './link.js'
import type { RelayTransport } from './transport.js'

const NOW = 1_800_000_000
/** The welcome key, recomputed here so a test can seal a body the encoder
 *  would refuse to write. */
const welcome = (bearer: Uint8Array) => hkdf(sha256, bearer, undefined, 'kithmoot/v3/group-invitation-key', 32)
function setup() {
  const host = createRoomInvitation(true)
  const secret = generateRoomSecret()
  const event = encodePersistentInvitation({ ...host, roomSecret: secret, now: NOW })
  return { host, secret, event }
}

function replay(events: Event[], eose = true): RelayTransport & { closed: boolean } {
  return {
    closed: false,
    async publish() { throw new Error('joining a group must not publish an admission request') },
    subscribe(_filters, onEvent, onEose) {
      for (const event of events) onEvent(event)
      if (eose) onEose?.()
      return () => { this.closed = true }
    },
    close() {},
  }
}

describe('persistent group invitations', () => {
  it('joins weeks later with nobody online, without granting an inviter signing key', async () => {
    const { host, secret, event } = setup()
    const transport = replay([event])
    const admission = await requestPersistentRoomAdmission({ transport, invitation: host.invitation })
    expect(admission).toEqual({ secret, persistent: true, epoch: 0 })
    expect(transport.closed).toBe(true)
    expect(event.kind).toBeLessThan(10000)
    expect(event.content).not.toContain(base64urlnopad.encode(secret))
    expect(event.tags).toHaveLength(1)
  })

  it('requires the pinned signer, correct bearer, unmodified ciphertext and explicit group mode', () => {
    const { host, event } = setup()
    expect(decodePersistentInvitation(finalizeEvent({ ...event }, generateSecretKey()), host.invitation)).toBeNull()
    expect(decodePersistentInvitation(event, { ...host.invitation, bearer: generateRoomSecret() })).toBeNull()
    expect(decodePersistentInvitation({ ...event, content: event.content.slice(0, -4) + 'AAAA' }, host.invitation)).toBeNull()
    const { persistent: _, ...temporary } = host.invitation
    expect(decodePersistentInvitation(event, temporary)).toBeNull()
    expect(() => encodePersistentInvitation({ ...host, invitation: temporary, roomSecret: generateRoomSecret(), now: NOW })).toThrow(/persistent/)
    expect(() => encodePersistentInvitation({ ...host, inviterSk: generateSecretKey(), roomSecret: generateRoomSecret(), now: NOW })).toThrow(/only the inviter/)
  })

  it.each([true, false])('retirement wins regardless of replay order (welcome first: %s)', async first => {
    const { host, event } = setup()
    const retired = encodeInvitationRetirement({ ...host, now: NOW + 86400 })
    const transport = replay(first ? [event, retired] : [retired, event])
    await expect(requestPersistentRoomAdmission({ transport, invitation: host.invitation })).rejects.toThrow(/retired/)
    expect(transport.closed).toBe(true)
  })

  it('a group whose room was ended says so rather than only that the link is retired', async () => {
    const { host, event } = setup()
    const transport = replay([event, encodeInvitationRetirement({ ...host, now: NOW + 60, ended: true })])
    await expect(requestPersistentRoomAdmission({ transport, invitation: host.invitation })).rejects.toThrow(ROOM_ENDED_MESSAGE)
  })

  it('does not admit on a partial result or unavailable relay', async () => {
    const { host, event } = setup()
    const transport = replay([event], false)
    await expect(requestPersistentRoomAdmission({ transport, invitation: host.invitation, timeoutMs: 5 })).rejects.toThrow(/could not be loaded/)
    expect(transport.closed).toBe(true)
    await expect(requestPersistentRoomAdmission({ transport: replay([]), invitation: host.invitation })).rejects.toThrow(/not available/)
  })

  it('ignores a forged retirement and rejects conflicting signed rooms', async () => {
    const { host, event } = setup()
    const retired = encodeInvitationRetirement({ ...host, now: NOW })
    const forged = finalizeEvent({ ...retired }, generateSecretKey())
    await expect(requestPersistentRoomAdmission({ transport: replay([forged, event]), invitation: host.invitation })).resolves.toHaveProperty('persistent', true)
    const conflict = encodePersistentInvitation({ ...host, roomSecret: generateRoomSecret(), now: NOW + 1 })
    await expect(requestPersistentRoomAdmission({ transport: replay([event, conflict]), invitation: host.invitation })).rejects.toThrow(/conflicting/)
  })

  it('round trips a v3 group link without a traffic secret; v2 stays temporary', () => {
    const { host } = setup()
    const url = encodeRoomLink('https://example.com/j/', { invitation: host.invitation, relays: ['wss://example.com'], iceUrls: [], name: 'Family' })
    expect(parseRoomLink(url).invitation).toEqual(host.invitation)
    const body = JSON.parse(new TextDecoder().decode(base64urlnopad.decode(new URL(url).hash.slice(1))))
    expect(body.v).toBe(3)
    expect(body.s).toBeUndefined()
    const temporary = createRoomInvitation()
    expect(parseRoomLink(encodeRoomLink('https://example.com/', { invitation: temporary.invitation, relays: [], iceUrls: [] })).invitation?.persistent).toBeUndefined()
  })

  it('a conference room carries its end in the body and as a NIP-40 expiration', async () => {
    const host = createRoomInvitation(true)
    const secret = generateRoomSecret()
    const ends = NOW + 86_400
    const event = encodePersistentInvitation({ ...host, roomSecret: secret, now: NOW, endsAt: ends })
    expect(event.tags).toEqual([['d', deriveInvitationId(host.invitation)], ['expiration', String(ends)]])
    expect(JSON.parse(nip44.v2.decrypt(event.content, welcome(host.invitation.bearer)))).toMatchObject({ v: 3, ends })
    expect(decodePersistentInvitation(event, host.invitation)).toEqual({ secret, persistent: true, epoch: 0, endsAt: ends })
    await expect(requestPersistentRoomAdmission({ transport: replay([event]), invitation: host.invitation }))
      .resolves.toEqual({ secret, persistent: true, epoch: 0, endsAt: ends })
  })

  it('a group with no end is byte for byte what it was, and decodes with no endsAt', () => {
    const { host, secret, event } = setup()
    expect(event.tags).toEqual([['d', deriveInvitationId(host.invitation)]])
    const body = JSON.parse(nip44.v2.decrypt(event.content, welcome(host.invitation.bearer)))
    expect(Object.keys(body).sort()).toEqual(['room', 'secret', 'v'])
    const decoded = decodePersistentInvitation(event, host.invitation)
    expect(decoded).toEqual({ secret, persistent: true, epoch: 0 })
    expect(decoded).not.toHaveProperty('endsAt')
  })

  it('refuses to encode an end in the past, now, or more than 30 days ahead', () => {
    const host = createRoomInvitation(true)
    const roomSecret = generateRoomSecret()
    expect(() => encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW })).toThrow(/past/)
    expect(() => encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW - 60 })).toThrow(/past/)
    expect(() => encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 30 * 86_400 + 1 })).toThrow(/30 days/)
    expect(() => encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 1.5 })).toThrow(/whole number/)
    expect(encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 30 * 86_400 }).tags).toHaveLength(2)
  })

  it('refuses an expiration tag that does not match the body end', () => {
    const host = createRoomInvitation(true)
    const roomSecret = generateRoomSecret()
    const ends = NOW + 3_600
    const withEnds = encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: ends })
    const without = encodePersistentInvitation({ ...host, roomSecret, now: NOW })
    const d = ['d', deriveInvitationId(host.invitation)]
    const resign = (event: Event, tags: string[][]) => finalizeEvent({ kind: event.kind, created_at: event.created_at, tags, content: event.content }, host.inviterSk)
    // A different expiration from the body's end.
    expect(decodePersistentInvitation(resign(withEnds, [d, ['expiration', String(ends + 1)]]), host.invitation)).toBeNull()
    // An expiration with no end in the body.
    expect(decodePersistentInvitation(resign(without, [d, ['expiration', String(ends)]]), host.invitation)).toBeNull()
    // Two expirations, even when one agrees.
    expect(decodePersistentInvitation(resign(withEnds, [d, ['expiration', String(ends)], ['expiration', String(ends)]]), host.invitation)).toBeNull()
    // A body end with no tag is still the room's end: the tag is for relays.
    expect(decodePersistentInvitation(resign(withEnds, [d]), host.invitation)).toEqual({ secret: roomSecret, persistent: true, epoch: 0, endsAt: ends })
  })

  it('refuses a body end that is not a positive whole number of seconds', () => {
    const host = createRoomInvitation(true)
    const roomSecret = generateRoomSecret()
    const room = deriveRoom(roomSecret).roomId
    for (const ends of [0, -1, 1.5, '1800003600', null]) {
      const event = finalizeEvent({
        kind: KINDS.GROUP_INVITATION,
        created_at: NOW,
        tags: [['d', deriveInvitationId(host.invitation)]],
        content: nip44.v2.encrypt(JSON.stringify({ v: 3, room, secret: base64urlnopad.encode(roomSecret), ends }), welcome(host.invitation.bearer)),
      }, host.inviterSk)
      expect(decodePersistentInvitation(event, host.invitation)).toBeNull()
    }
  })

  it('two signed copies that disagree on the end admit with the earlier one', async () => {
    const host = createRoomInvitation(true)
    const roomSecret = generateRoomSecret()
    const early = encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 3_600 })
    const late = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 1, endsAt: NOW + 7_200 })
    const none = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 2 })
    for (const order of [[early, late, none], [none, late, early]]) {
      await expect(requestPersistentRoomAdmission({ transport: replay(order), invitation: host.invitation })).resolves.toHaveProperty('endsAt', NOW + 3_600)
    }
  })

  it('a conference room\'s retirement lapses with it', () => {
    const host = createRoomInvitation(true)
    const ends = NOW + 86_400
    const retired = encodeInvitationRetirement({ ...host, now: NOW + 60, ended: true, endsAt: ends })
    expect(retired.tags).toEqual([['d', deriveInvitationId(host.invitation)], ['expiration', String(ends)]])
    expect(decodeInvitationRetirementNotice(retired, host.invitation)).toEqual({ ended: true })
    expect(encodeInvitationRetirement({ ...host, now: NOW }).tags).toEqual([['d', deriveInvitationId(host.invitation)]])
  })

  describe('room relays', () => {
    const RELAYS = ['wss://relay.example.com/', 'wss://relay.example.org/nostr', 'ws://localhost:7777/']
    /** Seal any body under the welcome key, as a writer the encoder would refuse. */
    function sealed(host: ReturnType<typeof createRoomInvitation>, roomSecret: Uint8Array, extra: Record<string, unknown>, now = NOW) {
      return finalizeEvent({
        kind: KINDS.GROUP_INVITATION,
        created_at: now,
        tags: [['d', deriveInvitationId(host.invitation)]],
        content: nip44.v2.encrypt(JSON.stringify({ v: 3, room: deriveRoom(roomSecret).roomId, secret: base64urlnopad.encode(roomSecret), ...extra }), welcome(host.invitation.bearer)),
      }, host.inviterSk)
    }

    it('round trips the room relays, in order, through the signed invitation', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const event = encodePersistentInvitation({ ...host, roomSecret, now: NOW, relays: RELAYS })
      expect(event.tags).toEqual([['d', deriveInvitationId(host.invitation)]])
      expect(decodePersistentInvitation(event, host.invitation)).toEqual({ secret: roomSecret, persistent: true, epoch: 0, relays: RELAYS })
      await expect(requestPersistentRoomAdmission({ transport: replay([event]), invitation: host.invitation }))
        .resolves.toEqual({ secret: roomSecret, persistent: true, epoch: 0, relays: RELAYS })
    })

    it('writes the body keys in the order v, room, secret, ends, relays', () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const both = encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 3_600, relays: RELAYS })
      expect(Object.keys(JSON.parse(nip44.v2.decrypt(both.content, welcome(host.invitation.bearer))))).toEqual(['v', 'room', 'secret', 'ends', 'relays'])
      const relaysOnly = encodePersistentInvitation({ ...host, roomSecret, now: NOW, relays: RELAYS })
      expect(Object.keys(JSON.parse(nip44.v2.decrypt(relaysOnly.content, welcome(host.invitation.bearer))))).toEqual(['v', 'room', 'secret', 'relays'])
      expect(decodePersistentInvitation(both, host.invitation)).toEqual({ secret: roomSecret, persistent: true, epoch: 0, endsAt: NOW + 3_600, relays: RELAYS })
    })

    it('with no relays, the plaintext is byte for byte what 0.3.0 wrote', () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const room = deriveRoom(roomSecret).roomId
      const secret = base64urlnopad.encode(roomSecret)
      const plain = (event: Event) => nip44.v2.decrypt(event.content, welcome(host.invitation.bearer))
      expect(plain(encodePersistentInvitation({ ...host, roomSecret, now: NOW }))).toBe(`{"v":3,"room":"${room}","secret":"${secret}"}`)
      expect(plain(encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 60 })))
        .toBe(`{"v":3,"room":"${room}","secret":"${secret}","ends":${NOW + 60}}`)
      expect(decodePersistentInvitation(encodePersistentInvitation({ ...host, roomSecret, now: NOW }), host.invitation)).not.toHaveProperty('relays')
    })

    it.each<[string, unknown]>([
      ['empty', []],
      ['more than eight', Array.from({ length: 9 }, (_, i) => `wss://relay${i}.example.com/`)],
      ['repeated', ['wss://relay.example.com/', 'wss://relay.example.com/']],
      ['not a string', ['wss://relay.example.com/', 7]],
      ['plain ws off loopback', ['ws://relay.example.com/']],
      ['an https URL', ['https://relay.example.com/']],
      ['not canonical: no trailing slash', ['wss://relay.example.com']],
      ['not canonical: upper case', ['wss://Relay.Example.com/']],
      ['not canonical: default port', ['wss://relay.example.com:443/']],
      ['not canonical: trailing path slash', ['wss://relay.example.com/nostr/']],
      ['credentials', ['wss://user:pw@relay.example.com/']],
      ['a fragment', ['wss://relay.example.com/#x']],
      ['not a list', 'wss://relay.example.com/'],
      ['null', null],
    ])('refuses the whole envelope when the relays are %s', (_label, relays) => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      expect(decodePersistentInvitation(sealed(host, roomSecret, { relays }), host.invitation)).toBeNull()
      if (Array.isArray(relays)) expect(() => encodePersistentInvitation({ ...host, roomSecret, now: NOW, relays: relays as string[] })).toThrow(/relay/)
    })

    it('accepts exactly eight relays', () => {
      const host = createRoomInvitation(true)
      const relays = Array.from({ length: 8 }, (_, i) => `wss://relay${i}.example.com/`)
      const event = encodePersistentInvitation({ ...host, roomSecret: generateRoomSecret(), now: NOW, relays })
      expect(decodePersistentInvitation(event, host.invitation)?.relays).toEqual(relays)
    })

    it('a reader that knows nothing of a newer key still decodes the invitation', () => {
      // What makes the field safe for a 0.3.0 reader: an unknown key is ignored.
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      expect(decodePersistentInvitation(sealed(host, roomSecret, { relays: RELAYS, later: { anything: true } }), host.invitation))
        .toEqual({ secret: roomSecret, persistent: true, epoch: 0, relays: RELAYS })
    })

    it('two signed copies that disagree on the relays admit with the newest that names any', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const older = encodePersistentInvitation({ ...host, roomSecret, now: NOW, relays: ['wss://old.example.com/'] })
      const newer = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 10, relays: ['wss://new.example.com/'] })
      const silent = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 20 })
      for (const order of [[older, newer, silent], [silent, newer, older], [newer, silent, older], [older, silent, newer]]) {
        await expect(requestPersistentRoomAdmission({ transport: replay(order), invitation: host.invitation }))
          .resolves.toHaveProperty('relays', ['wss://new.example.com/'])
      }
      await expect(requestPersistentRoomAdmission({ transport: replay([silent]), invitation: host.invitation })).resolves.not.toHaveProperty('relays')
      // Equal timestamps: the first copy heard stands.
      const twin = encodePersistentInvitation({ ...host, roomSecret, now: NOW, relays: ['wss://twin.example.com/'] })
      await expect(requestPersistentRoomAdmission({ transport: replay([older, twin]), invitation: host.invitation }))
        .resolves.toHaveProperty('relays', ['wss://old.example.com/'])
    })

    it('the relays and the end merge independently: newest relays, earliest end', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const early = encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 3_600, relays: ['wss://old.example.com/'] })
      const late = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 10, endsAt: NOW + 7_200, relays: ['wss://new.example.com/'] })
      for (const order of [[early, late], [late, early]]) {
        await expect(requestPersistentRoomAdmission({ transport: replay(order), invitation: host.invitation }))
          .resolves.toEqual({ secret: roomSecret, persistent: true, epoch: 0, endsAt: NOW + 3_600, relays: ['wss://new.example.com/'] })
      }
    })
  })

  describe('self-destructing rooms', () => {
    /** Seal any body under the welcome key, as a writer the encoder would refuse. */
    function sealed(host: ReturnType<typeof createRoomInvitation>, roomSecret: Uint8Array, extra: Record<string, unknown>, now = NOW) {
      return finalizeEvent({
        kind: KINDS.GROUP_INVITATION,
        created_at: now,
        tags: [['d', deriveInvitationId(host.invitation)]],
        content: nip44.v2.encrypt(JSON.stringify({ v: 3, room: deriveRoom(roomSecret).roomId, secret: base64urlnopad.encode(roomSecret), ...extra }), welcome(host.invitation.bearer)),
      }, host.inviterSk)
    }
    const RELAYS = ['wss://relay.example.com/']

    it('round trips the flag inside the encrypted body, never as a tag', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const ends = NOW + 3_600
      const event = encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: ends, destruct: true })
      expect(event.tags).toEqual([['d', deriveInvitationId(host.invitation)], ['expiration', String(ends)]])
      expect(JSON.stringify(event.tags)).not.toContain('destruct')
      expect(decodePersistentInvitation(event, host.invitation)).toEqual({ secret: roomSecret, persistent: true, epoch: 0, endsAt: ends, destruct: true })
      await expect(requestPersistentRoomAdmission({ transport: replay([event]), invitation: host.invitation }))
        .resolves.toEqual({ secret: roomSecret, persistent: true, epoch: 0, endsAt: ends, destruct: true })
    })

    it('needs no end: the room self-destructs when its authority closes it', () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const event = encodePersistentInvitation({ ...host, roomSecret, now: NOW, destruct: true })
      expect(event.tags).toEqual([['d', deriveInvitationId(host.invitation)]])
      expect(decodePersistentInvitation(event, host.invitation)).toEqual({ secret: roomSecret, persistent: true, epoch: 0, destruct: true })
    })

    it('writes the body keys in the order v, room, secret, ends, destruct, relays', () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const keys = (event: Event) => Object.keys(JSON.parse(nip44.v2.decrypt(event.content, welcome(host.invitation.bearer))))
      expect(keys(encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 60, destruct: true, relays: RELAYS })))
        .toEqual(['v', 'room', 'secret', 'ends', 'destruct', 'relays'])
      expect(keys(encodePersistentInvitation({ ...host, roomSecret, now: NOW, destruct: true }))).toEqual(['v', 'room', 'secret', 'destruct'])
    })

    it('omitted or false, the plaintext is byte for byte what 0.8.0 wrote', () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const room = deriveRoom(roomSecret).roomId
      const secret = base64urlnopad.encode(roomSecret)
      const plain = (event: Event) => nip44.v2.decrypt(event.content, welcome(host.invitation.bearer))
      for (const destruct of [undefined, false]) {
        const event = encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 60, relays: RELAYS, destruct })
        expect(plain(event)).toBe(`{"v":3,"room":"${room}","secret":"${secret}","ends":${NOW + 60},"relays":${JSON.stringify(RELAYS)}}`)
        expect(decodePersistentInvitation(event, host.invitation)).not.toHaveProperty('destruct')
      }
      expect(plain(encodePersistentInvitation({ ...host, roomSecret, now: NOW, destruct: true })))
        .toBe(`{"v":3,"room":"${room}","secret":"${secret}","destruct":true}`)
    })

    it.each<[string, unknown]>([
      ['false', false],
      ['a string', 'true'],
      ['a number', 1],
      ['null', null],
      ['an object', {}],
    ])('refuses the whole envelope when the flag is %s', (_label, destruct) => {
      const host = createRoomInvitation(true)
      expect(decodePersistentInvitation(sealed(host, generateRoomSecret(), { destruct }), host.invitation)).toBeNull()
    })

    it('two signed copies that disagree on self-destruct admit with it, in any order', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const flagged = encodePersistentInvitation({ ...host, roomSecret, now: NOW, destruct: true })
      const plain = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 10 })
      const later = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 20, relays: RELAYS })
      for (const order of [[flagged, plain], [plain, flagged], [flagged, plain, later], [later, plain, flagged]]) {
        await expect(requestPersistentRoomAdmission({ transport: replay(order), invitation: host.invitation }))
          .resolves.toHaveProperty('destruct', true)
      }
      await expect(requestPersistentRoomAdmission({ transport: replay([plain, later]), invitation: host.invitation }))
        .resolves.not.toHaveProperty('destruct')
    })

    it('merges independently of the end and the relays', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const early = encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 3_600, destruct: true })
      const late = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 10, endsAt: NOW + 7_200, relays: RELAYS })
      for (const order of [[early, late], [late, early]]) {
        await expect(requestPersistentRoomAdmission({ transport: replay(order), invitation: host.invitation }))
          .resolves.toEqual({ secret: roomSecret, persistent: true, epoch: 0, endsAt: NOW + 3_600, relays: RELAYS, destruct: true })
      }
    })

    it('an ended room\'s retirement may say it self-destructs; a joiner is still told the room ended', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const event = encodePersistentInvitation({ ...host, roomSecret, now: NOW, destruct: true })
      const retired = encodeInvitationRetirement({ ...host, now: NOW + 60, ended: true, destruct: true })
      expect(decodeInvitationRetirementNotice(retired, host.invitation)).toEqual({ ended: true, destruct: true })
      await expect(requestPersistentRoomAdmission({ transport: replay([event, retired]), invitation: host.invitation })).rejects.toThrow(ROOM_ENDED_MESSAGE)
    })
  })

  // The upstream kithmoot suite also has a test here that joins via
  // `RoomAgent.join` (`app`-level agent runtime) to prove an agent can send
  // chat from stored admission alone. `RoomAgent` is not part of the kit's
  // boundary (see EXTRACTION.md), so that integration test stays in
  // KithMoot; `SimRelay`/`SimTransport` above already exercise the same
  // stored-event replay path this kit owns.
})
