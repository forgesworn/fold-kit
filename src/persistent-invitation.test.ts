import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/pure'
import { base64urlnopad } from '@scure/base'
import { createRoomInvitation, encodeInvitationRetirement, ROOM_ENDED_MESSAGE } from './invitation.js'
import { encodePersistentInvitation, decodePersistentInvitation, requestPersistentRoomAdmission } from './persistent-invitation.js'
import { generateRoomSecret } from './room.js'
import { encodeRoomLink, parseRoomLink } from './link.js'
import type { RelayTransport } from './transport.js'

const NOW = 1_800_000_000
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

  // The upstream kithmoot suite also has a test here that joins via
  // `RoomAgent.join` (`app`-level agent runtime) to prove an agent can send
  // chat from stored admission alone. `RoomAgent` is not part of the kit's
  // boundary (see docs/plans/2026-09-28-circle-kit-extraction.md §1.1/§1.2
  // in the girnel repository), so that integration test stays in KithMoot;
  // `SimRelay`/`SimTransport` above already exercise the same stored-event
  // replay path this kit owns.
})
