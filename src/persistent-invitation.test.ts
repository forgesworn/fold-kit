import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/pure'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { createRoomInvitation, decodeInvitationRetirementNotice, deriveInvitationId, encodeInvitationRetirement, roomInvitation, ROOM_ENDED_MESSAGE } from './invitation.js'
import { KINDS } from './kinds.js'
import { encodePersistentInvitation, decodePersistentInvitation, requestPersistentRoomAdmission } from './persistent-invitation.js'
import { deriveRoom, generateRoomSecret } from './room.js'
import { encodeRoomLink, parseRoomLink } from './link.js'
import type { RelayTransport } from './transport.js'
import { hexToBytes } from '@noble/hashes/utils'
import { ACCEPTS, REFUSALS } from '../test/storage-fixtures.js'

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

  describe('storage nodes', () => {
    const NODES = ['https://grove.example.net', 'https://example.org:8443/wb', 'http://127.0.0.1:8080']
    /** Seal any body under the welcome key, as a writer the encoder would refuse. */
    function sealed(host: ReturnType<typeof createRoomInvitation>, roomSecret: Uint8Array, extra: Record<string, unknown>, now = NOW) {
      return finalizeEvent({
        kind: KINDS.GROUP_INVITATION,
        created_at: now,
        tags: [['d', deriveInvitationId(host.invitation)]],
        content: nip44.v2.encrypt(JSON.stringify({ v: 3, room: deriveRoom(roomSecret).roomId, secret: base64urlnopad.encode(roomSecret), ...extra }), welcome(host.invitation.bearer)),
      }, host.inviterSk)
    }
    const admit = (events: Event[], host: ReturnType<typeof createRoomInvitation>) => requestPersistentRoomAdmission({ transport: replay(events), invitation: host.invitation })

    it('round trips the nodes, in order, through the signed invitation', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const event = encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage: NODES })
      expect(event.tags).toEqual([['d', deriveInvitationId(host.invitation)]])
      const expected = { secret: roomSecret, persistent: true, epoch: 0, storage: NODES, storageAt: NOW }
      expect(decodePersistentInvitation(event, host.invitation)).toEqual(expected)
      await expect(admit([event], host)).resolves.toEqual(expected)
    })

    it('writes the body keys in the order v, room, secret, ends, destruct, relays, storage', () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const keys = (e: Event) => Object.keys(JSON.parse(nip44.v2.decrypt(e.content, welcome(host.invitation.bearer))))
      const all = encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 3_600, destruct: true, relays: ['wss://relay.example.com/'], storage: NODES })
      expect(keys(all)).toEqual(['v', 'room', 'secret', 'ends', 'destruct', 'relays', 'storage'])
      expect(keys(encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage: NODES }))).toEqual(['v', 'room', 'secret', 'storage'])
      expect(decodePersistentInvitation(all, host.invitation)).toEqual({
        secret: roomSecret, persistent: true, epoch: 0, endsAt: NOW + 3_600, destruct: true, relays: ['wss://relay.example.com/'], storage: NODES, storageAt: NOW,
      })
    })

    it('with no storage, the event is byte for byte what 0.13.0 wrote', () => {
      // Two events recorded from 0.13.0's encoder (commit 020d85e) with fixed
      // keys and recorded random draws; today's encoder must rebuild them exactly.
      const inviterSk = hexToBytes('e11427318417b9718102f054bce1c78d9d45cb2930636ee9e78cf458051a1327')
      const invitation = roomInvitation(hexToBytes('1e6878787b76900c6275de47b001e14f1d77f8457e7282398caa050f74cf57e8'), getPublicKey(inviterSk), true)
      const roomSecret = hexToBytes('11e78be7638c5b993fa901d5a23d9ffe409cab954c83112fd1997a694fd188ac')
      const recorded013 = {
        plain: { draws: ['861422685b9f326b36f30b43e2ab2e83d979d760c2a17ece4760200719e213f8', '1555e1197c43e347def533660229c9f7d5f63285b842d59e7518c5068f7abf24'], event: {"id": "ca2271cae9b3e6657b6de88b5d444f2d556377207be1775541f5cc288ce9cb93", "pubkey": "caddad97f8824376a936b17ac2c0f5bbe2c6038e1b581f21c7015517466f118a", "created_at": 1800000000, "kind": 1463, "tags": [["d", "53d54d568559f777c1ec1e7e2c9fa805277b4fb51cd217b97560eac815605025"]], "content": "AoYUImhbnzJrNvMLQ+KrLoPZeddgwqF+zkdgIAcZ4hP4z79xrlnUNdV31FZGDbMmbHM+pPHaNPXFciplA0au/qrjURkmdAD6Acaplu9RlmPA8GeChMaOZuaNR5W7ShLJCQUE32kqfDTIUW5UuVptFBEDCbi5KzCBHfAfvqxrlvgYlBufAtl5l1VsA6AFUHC2xM7r75cBJqMN5DEEgvPUIeKQhlaqKvjjgC5ce2t6eR6Poi7/4VVTbRSWZ3nwUC0h78Wy65OZMsT5jOd9dWgMnj+ml0FmWB3NIqOuSMvkjpRTqVM=", "sig": "3542c9cffa6ab6189626b83242bda3e77e2b9b56220d1027fc5abcb501f5568af51d357d35a638b4175aed6ddbb0f8030cff0975fac392a869119fdb21538a08"} },
        full: { draws: ['527137715b237d3c7f53ca4655afad30a1ffce980d5302dad9ed4c7ea6dd9589', '51de167159d7c60e22cb968f887b00507711c2b412529162a88dcaf83e36101c'], event: {"id": "5042b581b34988f7fa435010ddd33ddf437f718da678019501a81867f2677e90", "pubkey": "caddad97f8824376a936b17ac2c0f5bbe2c6038e1b581f21c7015517466f118a", "created_at": 1800000000, "kind": 1463, "tags": [["d", "53d54d568559f777c1ec1e7e2c9fa805277b4fb51cd217b97560eac815605025"], ["expiration", "1800086400"]], "content": "AlJxN3FbI308f1PKRlWvrTCh/86YDVMC2tntTH6m3ZWJzWz6qjlH8Q1tCaUkgWWg+Y5U3N6BbaReK8o5X59hQdbhlxS2VQwzWyDPhBWIjM6GUc7o0ohRq5xDJx0YCyytDwQlWYbuk5me5zeiklTzaLEIFd6MNSyN++kuz2a58m978yI8ZqFUFxataoDAS2A8NBdr/IQxfpvq2FtvfZJO8JjI1cZnI2QIjV2EhaQ1VxX4pOWcU86a9anXRBT333/zpGAUgq2DoyyYiMJXWkAH+v3qsReLMYfa+/14ePHPKvwWBZmHfpMtDfpWHZy0yQis+unLJNhbpmAO8I15kMGp+jH26Y/YlADQk+xMLQ8cfHIyS0FszXH2ziSAKy9CAjC5Jkm5", "sig": "37266a53d6f4c12bd42f9d466e0c524d31e79cbb97c1db39fa34771ae3fd4d0b24b1cab51b7b8cd6465a4929ba227203593788711f3fd5ffed8838ba3c411d54"} },
      }
      const options = { invitation, inviterSk, roomSecret, now: 1_800_000_000 }
      const build = (draws: string[], extra: object): Event => {
        const queue = draws.map(hexToBytes)
        const original = globalThis.crypto.getRandomValues.bind(globalThis.crypto)
        globalThis.crypto.getRandomValues = (<T extends ArrayBufferView | null>(array: T): T => {
          const next = queue.shift()
          if (!next) throw new Error('more random draws than recorded')
          ;(array as unknown as Uint8Array).set(next)
          return array
        }) as typeof globalThis.crypto.getRandomValues
        try {
          const event = encodePersistentInvitation({ ...options, ...extra })
          if (queue.length) throw new Error('fewer random draws than recorded')
          const { id, pubkey, created_at, kind, tags, content, sig } = event
          return { id, pubkey, created_at, kind, tags, content, sig }
        } finally { globalThis.crypto.getRandomValues = original }
      }
      expect(build(recorded013.plain.draws, {})).toEqual(recorded013.plain.event)
      expect(build(recorded013.full.draws, { endsAt: 1_800_086_400, destruct: true, relays: ['wss://relay.example.com/'] })).toEqual(recorded013.full.event)
      // The 0.13.0 events still decode to an admission with no storage.
      expect(decodePersistentInvitation(recorded013.plain.event, invitation)).toEqual({ secret: roomSecret, persistent: true, epoch: 0 })
      expect(decodePersistentInvitation(recorded013.full.event, invitation)).not.toHaveProperty('storage')
      expect(decodePersistentInvitation(recorded013.full.event, invitation)).not.toHaveProperty('storageAt')
      // And the plaintext spelling, as for relays.
      const host = createRoomInvitation(true)
      const secret = generateRoomSecret()
      const text = (e: Event) => nip44.v2.decrypt(e.content, welcome(host.invitation.bearer))
      expect(text(encodePersistentInvitation({ ...host, roomSecret: secret, now: NOW })))
        .toBe(`{"v":3,"room":"${deriveRoom(secret).roomId}","secret":"${base64urlnopad.encode(secret)}"}`)
    })

    it('round trips an empty list, which says the authority withdrew every node', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const event = encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage: [] })
      expect(nip44.v2.decrypt(event.content, welcome(host.invitation.bearer))).toContain(',"storage":[]}')
      const expected = { secret: roomSecret, persistent: true, epoch: 0, storage: [], storageAt: NOW }
      expect(decodePersistentInvitation(event, host.invitation)).toEqual(expected)
      await expect(admit([event], host)).resolves.toEqual(expected)
    })

    it.each([...ACCEPTS.map(([entry]) => [`accepts ${entry}`, [entry], true] as const), ...REFUSALS.map(([label, entry]) => [`refuses ${label}`, [entry], false] as const)])(
      'the whole envelope %s', (_name, storage, accepted) => {
        const host = createRoomInvitation(true)
        const roomSecret = generateRoomSecret()
        const decoded = decodePersistentInvitation(sealed(host, roomSecret, { storage }), host.invitation)
        if (accepted) {
          expect(decoded?.storage).toEqual(storage)
          expect(() => encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage })).not.toThrow()
        } else {
          expect(decoded).toBeNull()
          expect(() => encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage })).toThrow(/storage node/)
        }
      })

    it.each<[string, unknown]>([
      ['not an array', 'https://grove.example.net'],
      ['null', null],
      ['a number', 7],
      ['an object', { 0: 'https://grove.example.net' }],
      ['a number in the list', ['https://grove.example.net', 7]],
      ['nine entries', Array.from({ length: 9 }, (_, i) => `https://node${i}.example.net`)],
      ['two ports on one host', ['https://example.net', 'https://example.net:8443']],
      ['the same entry twice', ['https://example.net', 'https://example.net']],
      ['an object entry', [{ base: 'https://example.net' }]],
    ])('refuses the whole envelope when the storage is %s', (_label, storage) => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      expect(decodePersistentInvitation(sealed(host, roomSecret, { storage }), host.invitation)).toBeNull()
      if (Array.isArray(storage)) expect(() => encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage: storage as string[] })).toThrow(/storage node/)
    })

    it('accepts exactly eight nodes', () => {
      const host = createRoomInvitation(true)
      const storage = Array.from({ length: 8 }, (_, i) => `https://node${i}.example.net`)
      const event = encodePersistentInvitation({ ...host, roomSecret: generateRoomSecret(), now: NOW, storage })
      expect(decodePersistentInvitation(event, host.invitation)?.storage).toEqual(storage)
    })

    it('a malformed storage refuses the envelope even beside good relays', () => {
      const host = createRoomInvitation(true)
      expect(decodePersistentInvitation(sealed(host, generateRoomSecret(), { relays: ['wss://relay.example.com/'], storage: ['http://example.net'] }), host.invitation)).toBeNull()
    })

    it('a reader that knows nothing of a newer key still decodes the invitation', () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      expect(decodePersistentInvitation(sealed(host, roomSecret, { storage: NODES, later: { anything: true } }), host.invitation))
        .toEqual({ secret: roomSecret, persistent: true, epoch: 0, storage: NODES, storageAt: NOW })
    })

    it('two signed copies that disagree on the nodes admit with the newest that names any', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const older = encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage: ['https://old.example.net'] })
      const newer = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 10, storage: ['https://new.example.net'] })
      const silent = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 20 })
      for (const order of [[older, newer, silent], [silent, newer, older], [newer, silent, older], [older, silent, newer]]) {
        const admission = await admit(order, host)
        expect(admission.storage).toEqual(['https://new.example.net'])
        expect(admission.storageAt).toBe(NOW + 10)
      }
      const alone = await admit([silent], host)
      expect(alone).not.toHaveProperty('storage')
      expect(alone).not.toHaveProperty('storageAt')
      // Equal timestamps: the first copy heard stands.
      const twin = encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage: ['https://twin.example.net'] })
      expect((await admit([older, twin], host)).storage).toEqual(['https://old.example.net'])
      expect((await admit([twin, older], host)).storage).toEqual(['https://twin.example.net'])
    })

    it('a copy without storage leaves the held list alone, whichever order it is heard in', async () => {
      // The keeper publishes a plain copy first and the copy with nodes after it.
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const plain = encodePersistentInvitation({ ...host, roomSecret, now: NOW - 1 })
      const withNodes = encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage: NODES })
      for (const order of [[plain, withNodes], [withNodes, plain]]) {
        await expect(admit(order, host)).resolves.toEqual({ secret: roomSecret, persistent: true, epoch: 0, storage: NODES, storageAt: NOW })
      }
      // Even a plain copy newer than the list leaves it standing.
      const later = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 50 })
      for (const order of [[withNodes, later], [later, withNodes]]) {
        expect((await admit(order, host)).storage).toEqual(NODES)
      }
    })

    it('an empty list stands when it is the newest, and loses when it is older', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const listed = encodePersistentInvitation({ ...host, roomSecret, now: NOW, storage: NODES })
      const withdrawn = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 30, storage: [] })
      for (const order of [[listed, withdrawn], [withdrawn, listed]]) {
        const admission = await admit(order, host)
        expect(admission.storage).toEqual([])
        expect(admission.storageAt).toBe(NOW + 30)
      }
      const olderEmpty = encodePersistentInvitation({ ...host, roomSecret, now: NOW - 30, storage: [] })
      for (const order of [[listed, olderEmpty], [olderEmpty, listed]]) {
        expect((await admit(order, host)).storage).toEqual(NODES)
      }
    })

    it('the nodes, the relays and the end merge independently', async () => {
      const host = createRoomInvitation(true)
      const roomSecret = generateRoomSecret()
      const first = encodePersistentInvitation({ ...host, roomSecret, now: NOW, endsAt: NOW + 3_600, relays: ['wss://old.example.com/'], storage: ['https://new.example.net'] })
      const second = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 10, endsAt: NOW + 7_200, relays: ['wss://new.example.com/'] })
      const third = encodePersistentInvitation({ ...host, roomSecret, now: NOW + 5, storage: ['https://old.example.net'] })
      for (const order of [[first, second, third], [third, second, first], [second, first, third]]) {
        const admission = await admit(order, host)
        expect(admission).toEqual({
          secret: roomSecret, persistent: true, epoch: 0, endsAt: NOW + 3_600,
          relays: ['wss://new.example.com/'], storage: ['https://old.example.net'], storageAt: NOW + 5,
        })
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
