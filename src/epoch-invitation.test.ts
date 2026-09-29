import { describe, expect, it } from 'vitest'
import { getPublicKey, type Event } from 'nostr-tools/pure'
import { deriveRoom } from './room.js'
import { createRoomInvitation, decodeInvitationRetirementNotice } from './invitation.js'
import { decodePersistentInvitation, encodePersistentInvitation } from './persistent-invitation.js'
import { parseRoomLink } from './link.js'
import { encodeEpochInvitationLink, parseEpochInvitationLink } from './epoch-link.js'
import {
  decodeEpochInvitation, encodeEpochInvitation, prepareEpochInvitation, requestEpochAdmission,
  type EpochInvitation,
} from './epoch-invitation.js'
import type { StoredEventQuery, StoredEventQueryResult } from './stored-query.js'

const authoritySk = new Uint8Array(32).fill(7)
const authority = getPublicKey(authoritySk)
const secret0 = new Uint8Array(32).fill(9)
const roomId = deriveRoom(secret0).roomId
const invitation: EpochInvitation = { v: 4, bearer: new Uint8Array(32).fill(12), inviter: authority }
const now = 1_900_000_000
const current = { epoch: 0, secret: secret0 }

function welcome(app?: Record<string, import('./epoch-invitation.js').JsonValue>, token = invitation): Event {
  return encodeEpochInvitation({ invitation: token, authoritySk, roomId, current, app, now })
}

function query(events: Event[], evidence: StoredEventQueryResult = {
  queried: ['wss://one.example', 'wss://two.example'],
  eosed: ['wss://one.example'], unavailable: ['wss://two.example'],
}): StoredEventQuery {
  return async (_filters, onEvent) => { for (const event of events) onEvent(event, 'wss://one.example'); return evidence }
}

describe('v4 current-epoch invitation wire and link', () => {
  it('holds only the current secret and signed root id, including an epoch beyond zero', () => {
    const secret3 = new Uint8Array(32).fill(19)
    const event = encodeEpochInvitation({ invitation, authoritySk, roomId,
      current: { epoch: 3, secret: secret3 }, app: { circle: 'quiet' }, now })
    expect(event.kind).toBe(1463)
    expect(event.tags).toHaveLength(1)
    expect(decodeEpochInvitation(event, invitation)).toEqual({ roomId, authority,
      current: { epoch: 3, secret: secret3 }, app: { circle: 'quiet' } })
    expect(event.content).not.toContain(Buffer.from(secret0).toString('hex'))
    expect(event.content).not.toContain(Buffer.from(secret3).toString('hex'))
    expect(() => encodeEpochInvitation({ invitation, authoritySk, roomId,
      current: { epoch: 0, secret: secret3 }, now })).toThrow('does not bind')
  })

  it('enforces the compact app UTF-8 byte boundary and strict JSON inputs', () => {
    expect(new TextEncoder().encode(JSON.stringify({ x: 'a'.repeat(248) })).length).toBe(256)
    expect(decodeEpochInvitation(welcome({ x: 'a'.repeat(248) }), invitation)?.app).toEqual({ x: 'a'.repeat(248) })
    expect(() => welcome({ x: 'a'.repeat(249) })).toThrow('256 UTF-8 bytes')
    expect(decodeEpochInvitation(welcome({ x: 'é'.repeat(124) }), invitation)?.app).toEqual({ x: 'é'.repeat(124) })
    expect(() => welcome({ x: 'é'.repeat(125) })).toThrow('256 UTF-8 bytes')
    expect(() => encodeEpochInvitation({ invitation, authoritySk, roomId, current,
      app: { x: Number.NaN } as never, now })).toThrow('strict JSON')
    expect(() => encodeEpochInvitation({ invitation, authoritySk, roomId, current,
      app: [] as never, now })).toThrow('JSON object')
    let nested: import('./epoch-invitation.js').JsonValue = 0
    for (let i = 0; i < 123; i++) nested = [nested]
    expect(new TextEncoder().encode(JSON.stringify({ x: nested })).length).toBe(253)
    expect(decodeEpochInvitation(welcome({ x: nested }), invitation)?.app).toEqual({ x: nested })
    const cycle: Record<string, unknown> = {}; cycle.self = cycle
    expect(() => encodeEpochInvitation({ invitation, authoritySk, roomId, current,
      app: cycle as never, now })).toThrow('cycle')
  })

  it('keeps v3/v4 keys and link parsers separate and rejects altered authority, tags and signature', () => {
    const event = welcome()
    const v3 = createRoomInvitation(true)
    const old = encodePersistentInvitation({ invitation: v3.invitation, inviterSk: v3.inviterSk, roomSecret: secret0, now })
    expect(decodeEpochInvitation(old, invitation)).toBeNull()
    expect(decodePersistentInvitation(event, { bearer: invitation.bearer, inviter: authority, persistent: true })).toBeNull()
    expect(decodeEpochInvitation({ ...event, tags: [...event.tags, ['x', 'extra']] }, invitation)).toBeNull()
    expect(decodeEpochInvitation({ ...event, sig: '00'.repeat(64) }, invitation)).toBeNull()
    const link = encodeEpochInvitationLink('https://example.test/join', { invitation,
      relays: ['wss://one.example'], name: '  A   circle  ' })
    expect(link).not.toContain(Buffer.from(secret0).toString('base64url'))
    expect(parseEpochInvitationLink(link)).toEqual({ invitation, relays: ['wss://one.example'], name: 'A circle' })
    expect(() => parseRoomLink(link)).toThrow('unsupported version')
    expect(() => encodeEpochInvitationLink('https://example.test/join', { invitation,
      relays: ['ws://public.example'] })).toThrow('invalid relay')
  })

  it('rotates to a fresh bearer while retaining authority and retiring the previous one', () => {
    const prepared = prepareEpochInvitation({ authoritySk, roomId, current, previous: invitation, now })
    expect(prepared.invitation.inviter).toBe(authority)
    expect(prepared.invitation.bearer).not.toEqual(invitation.bearer)
    expect(decodeEpochInvitation(prepared.welcome, invitation)).toBeNull()
    expect(decodeEpochInvitation(prepared.welcome, prepared.invitation)?.current).toEqual(current)
    expect(decodeInvitationRetirementNotice(prepared.retirement!, invitation)).toEqual({ ended: false })
  })
})

describe('v4 stored admission', () => {
  it('waits for real EOSE and every queried source outcome', async () => {
    const event = welcome()
    await expect(requestEpochAdmission({ invitation, query: query([event], { queried: ['one'], eosed: [], unavailable: ['one'] }) }))
      .rejects.toThrow('real EOSE')
    await expect(requestEpochAdmission({ invitation, query: query([event], { queried: ['one', 'two'], eosed: ['one'], unavailable: [] }) }))
      .rejects.toThrow('every queried source')
    await expect(requestEpochAdmission({ invitation, query: query([event], { queried: Array(1), eosed: Array(1), unavailable: [] }) }))
      .rejects.toThrow('invalid source outcomes')
    expect((await requestEpochAdmission({ invitation, query: query([event]) })).current).toEqual(current)
  })

  it('lets retirement win before or after welcome and refuses same-bearer conflicting valid bodies', async () => {
    const event = welcome()
    const { retirement } = prepareEpochInvitation({ authoritySk, roomId, current, previous: invitation, now: now + 1 })
    await expect(requestEpochAdmission({ invitation, query: query([retirement!, event]) })).rejects.toThrow('retired')
    await expect(requestEpochAdmission({ invitation, query: query([event, retirement!]) })).rejects.toThrow('retired')
    const changed = encodeEpochInvitation({ invitation, authoritySk, roomId,
      current: { epoch: 1, secret: new Uint8Array(32).fill(10) }, now })
    await expect(requestEpochAdmission({ invitation, query: query([event, changed]) })).rejects.toThrow('conflicting')
    await expect(requestEpochAdmission({ invitation, query: query([event, welcome()]) })).resolves.toMatchObject({ roomId })
  })

  it('refuses a partial query, a withheld welcome and an overflow rather than admitting a subset', async () => {
    await expect(requestEpochAdmission({ invitation, query: query([]) })).rejects.toThrow('not available')
    const accepted = welcome()
    const events = [accepted, ...Array<Event>(256).fill({ ...accepted, kind: 999 })]
    await expect(requestEpochAdmission({ invitation, query: query(events) })).rejects.toThrow('incomplete')
    await expect(requestEpochAdmission({ invitation, query: async (_filters, onEvent) => {
      onEvent(welcome()); throw new Error('query timed out')
    } })).rejects.toThrow('timed out')
  })
})
