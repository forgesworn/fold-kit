import { describe, expect, it } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { nip44 } from 'nostr-tools'
import { finalizeEvent, getPublicKey, verifiedSymbol, type Event } from 'nostr-tools/pure'
import { deriveRoom } from './room.js'
import { encodePersistentInvitation } from './persistent-invitation.js'
import { decodeInvitationRequest, decodeRoomAdmissionGrant, encodeInvitationRequest, encodeInvitationGrant } from './invitation.js'
import {
  encodeLivePersistentDescriptor, decodeLivePersistentDescriptor,
  encodeLivePersistentRequest, decodeLivePersistentRequest,
  encodeLivePersistentAnswer, decodeLivePersistentAnswer,
  parseLivePersistentEvent,
} from './live-persistent-admission.js'

const now = 1_800_000_000
const root = new Uint8Array(32).fill(1)
const reply = new Uint8Array(32).fill(2)
const stranger = new Uint8Array(32).fill(3)
const secret = new Uint8Array(32).fill(4)
const bearer = new Uint8Array(32).fill(5)
const invitation = { bearer, inviter: getPublicKey(root), persistent: true as const }
const ctx = { invitation, roomId: deriveRoom(secret).roomId }
const reqKey = hkdf(sha256, bearer, undefined, 'kithmoot/v1/persistent-live/request-key', 32)
const answerKey = nip44.v2.utils.getConversationKey(root, getPublicKey(reply))

function fixture() {
  const request = encodeLivePersistentRequest({ ...ctx, requesterSk: reply, now })
  const invitationEvent = encodePersistentInvitation({ invitation, inviterSk: root, roomSecret: secret,
    now: now - 20, endsAt: now + 1000, relays: ['wss://relay.example/'], destruct: true })
  const answer = encodeLivePersistentAnswer({ ...ctx, request, invitationEvent, inviterSk: root, epoch: 2, now: now + 1 })
  const decode = (event: Event, changes = {}) => decodeLivePersistentAnswer(event, { ...ctx, request, requesterSk: reply, now: now + 2, ...changes })
  return { request, invitationEvent, answer, decode }
}

function signed(event: Event, changes: Partial<Event> = {}, sk = root): Event {
  return finalizeEvent({ kind: event.kind, created_at: event.created_at, tags: event.tags,
    content: event.content, ...changes }, sk)
}

function edited(event: Event, change: (raw: Record<string, unknown>) => void, request = false): Event {
  const key = request ? reqKey : answerKey
  const raw = JSON.parse(nip44.v2.decrypt(event.content, key)) as Record<string, unknown>
  change(raw)
  return signed(event, { content: nip44.v2.encrypt(JSON.stringify(raw), key) }, request ? reply : root)
}

describe('live persistent admission', () => {
  it('bounds raw JSON and rejects duplicate keys before event parsing discards them', () => {
    const { request } = fixture()
    const json = JSON.stringify(request)
    expect(parseLivePersistentEvent(json, true)).toEqual(JSON.parse(json))
    for (const bad of [json.replace('{', '{"kind":20466,'), json.replace('{', '{"extra":1,'),
      json.replace('{', '{ '), json.replace('"kind":20466', '"kind":"20466"'),
      json.replace('"kind":20466', '"kind":20466.0'), ' '.repeat(4097)]) {
      expect(parseLivePersistentEvent(bad, true)).toBeNull()
    }
  })
  it('returns epoch-zero capability and a separate current hint, with no delegation', () => {
    const { answer, decode } = fixture()
    const got = decode(answer)!
    expect(got.admission).toEqual({ secret, persistent: true, epoch: 0,
      endsAt: now + 1000, relays: ['wss://relay.example/'], destruct: true })
    expect(got.epochHint).toBe(2)
    expect(got.expiresAt).toBe(now + 31)
    expect(got.admission).not.toHaveProperty('delegate')
  })

  it('binds discovery to the original persistent invitation, not another bearer or root', () => {
    const encoded = encodeLivePersistentDescriptor(ctx)
    expect(decodeLivePersistentDescriptor(encoded, invitation)).toEqual(ctx)
    for (const wrong of [
      { ...invitation, bearer: stranger }, { ...invitation, inviter: getPublicKey(stranger) },
      { ...invitation, persistent: undefined },
    ]) expect(decodeLivePersistentDescriptor(encoded, wrong)).toBeNull()
    expect(decodeLivePersistentDescriptor(encoded + '=', invitation)).toBeNull()
    expect(decodeLivePersistentDescriptor('A'.repeat(513), invitation)).toBeNull()
    const raw = new TextDecoder().decode(base64urlnopad.decode(encoded))
    for (const bad of [raw.replace('{', '{"v":1,'), raw.replace('{', '{"extra":1,'), raw.replace('{', '{ '), raw.replace('"v":1', '"v":2')]) {
      expect(decodeLivePersistentDescriptor(base64urlnopad.encode(new TextEncoder().encode(bad)), invitation)).toBeNull()
    }
  })

  it('cannot be decoded as a legacy live request or delegation grant in either direction', () => {
    const { request, answer, decode } = fixture()
    expect(decodeInvitationRequest(request, { invitation, now })).toBeNull()
    expect(decodeRoomAdmissionGrant(answer, { invitation, requesterSk: reply, request: request.id, now })).toBeNull()
    const oldRequest = encodeInvitationRequest({ invitation, requesterSk: reply, now })
    expect(decodeLivePersistentRequest(oldRequest, { ...ctx, now })).toBeNull()
    const oldGrant = encodeInvitationGrant({ invitation, inviterSk: root, requester: getPublicKey(reply), request: request.id, roomSecret: secret, now })
    expect(decode(oldGrant)).toBeNull()
  })

  it('rejects response substitution by request, room, reply key, bearer or signer', () => {
    const { request, answer, decode } = fixture()
    const next = encodeLivePersistentRequest({ ...ctx, requesterSk: reply, now })
    expect(next.id).not.toBe(request.id)
    expect(decode(answer, { request: next })).toBeNull()
    expect(decode(answer, { requesterSk: stranger })).toBeNull()
    expect(decode(answer, { roomId: 'a'.repeat(64) })).toBeNull()
    expect(decode(answer, { invitation: { ...invitation, bearer: stranger } })).toBeNull()
    expect(decode(signed(answer, {}, stranger))).toBeNull()
    expect(decode(edited(answer, b => { b.request = next.id }))).toBeNull()
    expect(decode(edited(answer, b => { b.room = 'a'.repeat(64) }))).toBeNull()
  })

  it('rejects ambiguous routing tags on both profiles, but accepts their order changing', () => {
    const { request, answer, decode } = fixture()
    for (const name of ['d', 'p', 'expiration']) {
      for (const event of [request, answer]) {
        const original = event.tags.find(t => t[0] === name)!
        const sk = event === request ? reply : root
        const read = (e: Event) => event === request ? decodeLivePersistentRequest(e, { ...ctx, now }) : decode(e)
        expect(read(signed(event, { tags: [...event.tags, original] }, sk))).toBeNull()
        expect(read(signed(event, { tags: event.tags.filter(t => t[0] !== name) }, sk))).toBeNull()
        expect(read(signed(event, { tags: event.tags.map(t => t[0] === name ? [...t, 'extra'] : t) }, sk))).toBeNull()
        expect(read(signed(event, { tags: [...event.tags, ['extra', 'x']] }, sk))).toBeNull()
      }
    }
    expect(decode(signed(answer, { tags: [...answer.tags].reverse() }))).not.toBeNull()
    expect(decodeLivePersistentRequest(signed(request, { tags: [...request.tags].reverse() }, reply), { ...ctx, now })).not.toBeNull()
  })

  it('expires at the boundary, limits future skew and caps the answer to the request deadline', () => {
    const { request, invitationEvent, answer, decode } = fixture()
    expect(decodeLivePersistentRequest(request, { ...ctx, now: now - 5 })).not.toBeNull()
    expect(decodeLivePersistentRequest(request, { ...ctx, now: now - 6 })).toBeNull()
    expect(decodeLivePersistentRequest(request, { ...ctx, now: now + 89 })).not.toBeNull()
    expect(decodeLivePersistentRequest(request, { ...ctx, now: now + 90 })).toBeNull()
    expect(decode(answer, { now: now - 5 })).toBeNull()
    expect(decode(answer, { now: now + 30 })).not.toBeNull()
    expect(decode(answer, { now: now + 31 })).toBeNull()
    const late = encodeLivePersistentAnswer({ ...ctx, request, invitationEvent, inviterSk: root, epoch: 0, now: now + 89 })
    expect(decode(late, { now: now + 89 })?.expiresAt).toBe(now + 90)
    expect(decode(late, { now: now + 90 })).toBeNull()
    expect(() => encodeLivePersistentAnswer({ ...ctx, request, invitationEvent, inviterSk: root, epoch: 0, now: now + 90 })).toThrow()
    const tooEarly = signed(answer, { created_at: now - 6, tags: answer.tags.map(t => t[0] === 'expiration' ? ['expiration', String(now + 24)] : t) })
    expect(decode(tooEarly)).toBeNull()
  })

  it('rejects noncanonical or extended expiration and invalid local clocks', () => {
    const { request, answer, decode } = fixture()
    for (const value of ['0', String(now + 32), '1.8e9', ' 1800000031', '+1800000031', '01800000031', 'NaN']) {
      expect(decode(signed(answer, { tags: answer.tags.map(t => t[0] === 'expiration' ? ['expiration', value] : t) }))).toBeNull()
    }
    for (const clock of [-1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER]) {
      expect(decode(answer, { now: clock })).toBeNull()
      expect(() => encodeLivePersistentRequest({ ...ctx, now: clock, requesterSk: reply })).toThrow()
    }
    expect(decodeLivePersistentRequest(signed(request, { tags: request.tags.map(t => t[0] === 'expiration' ? ['expiration', String(now + 91)] : t) }, reply), { ...ctx, now })).toBeNull()
  })

  it('rejects wrong profile, body version, requester and unsafe epoch values', () => {
    const { request, answer, decode } = fixture()
    for (const value of [undefined, null, false, -1, 0.1, '2', Number.MAX_SAFE_INTEGER + 1]) {
      expect(decode(edited(answer, b => { b.epoch = value }))).toBeNull()
    }
    for (const [name, value] of [['v', 2], ['profile', 'legacy'], ['extra', true]]) {
      expect(decode(edited(answer, b => { b[name as string] = value }))).toBeNull()
      expect(decodeLivePersistentRequest(edited(request, b => { b[name as string] = value }, true), { ...ctx, now })).toBeNull()
    }
    expect(decodeLivePersistentRequest(edited(request, b => { b.requester = getPublicKey(stranger) }, true), { ...ctx, now })).toBeNull()
  })

  it('rejects duplicate encrypted JSON fields without relying on JSON.parse last-write wins', () => {
    const { request, answer, decode } = fixture()
    for (const event of [request, answer]) {
      const key = event === request ? reqKey : answerKey
      const plaintext = nip44.v2.decrypt(event.content, key)
      const altered = signed(event, { content: nip44.v2.encrypt(plaintext.replace('{', '{"v":1,'), key) }, event === request ? reply : root)
      expect(event === request ? decodeLivePersistentRequest(altered, { ...ctx, now }) : decode(altered)).toBeNull()
    }
  })

  it('bounds untrusted events and nested invitations before signature checks', () => {
    const { request, answer, decode } = fixture()
    expect(decode({ ...answer, content: 'A'.repeat(16385) })).toBeNull()
    expect(decodeLivePersistentRequest({ ...request, content: 'A'.repeat(2049) }, { ...ctx, now })).toBeNull()
    expect(decode(edited(answer, b => { (b.invitation as Event).content = 'A'.repeat(6145) }))).toBeNull()
    expect(decode(edited(answer, b => { (b.invitation as Event).tags = [['x', 'A'.repeat(257)]] }))).toBeNull()
    expect(decode(edited(answer, b => { b.invitation = null }))).toBeNull()
    expect(decode(edited(answer, b => { (b.invitation as unknown as Record<string, unknown>).extra = 1 }))).toBeNull()
    expect(decode({ ...answer, tags: [['p', getPublicKey(reply)], ...Array.from({ length: 9 }, () => ['x', 'x'])] })).toBeNull()
  })

  it('does not trust signature cache flags on outer or embedded events', () => {
    const { request, answer, decode } = fixture()
    expect(decode({ ...answer, content: (answer.content[0] === 'A' ? 'B' : 'A') + answer.content.slice(1), [verifiedSymbol]: true })).toBeNull()
    expect(decodeLivePersistentRequest({ ...request, pubkey: getPublicKey(stranger), [verifiedSymbol]: true }, { ...ctx, now })).toBeNull()
    expect(decode(edited(answer, b => { (b.invitation as Event).sig = '0'.repeat(128) }))).toBeNull()
  })

  it('checks embedded room, end time, self-destruct, relays and future timestamp', () => {
    const { invitationEvent, answer, decode } = fixture()
    const welcomeKey = hkdf(sha256, bearer, undefined, 'kithmoot/v3/group-invitation-key', 32)
    for (const changed of [
      { room: 'a'.repeat(64) }, { ends: now + 1 }, { destruct: false }, { relays: ['https://bad.example/'] },
    ]) {
      const welcome = JSON.parse(nip44.v2.decrypt(invitationEvent.content, welcomeKey))
      const bad = signed(invitationEvent, { content: nip44.v2.encrypt(JSON.stringify({ ...welcome, ...changed }), welcomeKey) })
      expect(decode(edited(answer, b => { b.invitation = bad }))).toBeNull()
    }
    const future = signed(invitationEvent, { created_at: now + 7 })
    expect(decode(edited(answer, b => { b.invitation = future }))).toBeNull()
    const otherRoom = encodePersistentInvitation({ invitation, inviterSk: root, roomSecret: stranger, now })
    expect(decode(edited(answer, b => { b.invitation = otherRoom }))).toBeNull()
  })

  it('requires the original live request, root key and valid invitation when encoding', () => {
    const { request, invitationEvent } = fixture()
    const opts = { ...ctx, request, invitationEvent, inviterSk: root, epoch: 0, now }
    expect(() => encodeLivePersistentAnswer({ ...opts, inviterSk: stranger })).toThrow()
    expect(() => encodeLivePersistentAnswer({ ...opts, epoch: -1 })).toThrow()
    expect(() => encodeLivePersistentAnswer({ ...opts, roomId: 'a'.repeat(64) })).toThrow()
    expect(() => encodeLivePersistentAnswer({ ...opts, invitationEvent: { ...invitationEvent, sig: '0'.repeat(128), [verifiedSymbol]: true } })).toThrow()
  })
})
