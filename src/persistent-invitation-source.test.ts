import { describe, expect, it, vi } from 'vitest'
import { finalizeEvent, generateSecretKey, verifiedSymbol, type Event } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { createRoomInvitation, deriveInvitationId, encodeInvitationRetirement } from './invitation.js'
import { encodePersistentInvitation, PERSISTENT_INVITATION_LABELS } from './persistent-invitation.js'
import { revalidatePersistentInvitationSource as validate, revalidatePersistentInvitationEvidence,
  MAX_PERSISTENT_INVITATION_EVENT_BYTES } from './persistent-invitation-evidence.js'
import * as verifier from './verify.js'
import * as rooms from './room.js'

const now = 1_800_000_000
function fixture() {
  const host = createRoomInvitation(true), secret = new Uint8Array(32).fill(42)
  const invite = (extra: Partial<Parameters<typeof encodePersistentInvitation>[0]> = {}) => encodePersistentInvitation({ ...host, roomSecret: secret, now, ...extra })
  return { host, secret, invite }
}
function canonical(event: Event) {
  return JSON.stringify({ id: event.id, pubkey: event.pubkey, created_at: event.created_at,
    kind: event.kind, tags: event.tags, content: event.content, sig: event.sig })
}

describe('single persistent invitation source', () => {
  it.each([{}, { endsAt: now + 100 }, { destruct: true }, { relays: ['wss://fixed.example/'] },
    { endsAt: now + 100, destruct: true, relays: ['wss://one.example/', 'wss://two.example/'] }])('revalidates actual encoder fields and exact canonical reload: %j', extra => {
    const f = fixture(), event = f.invite(extra)
    const source = validate({ event, invitation: f.host.invitation, expectedRoomSecret: f.secret })
    expect(source).toMatchObject({ version: 1, invitationId: deriveInvitationId(f.host.invitation),
      inviter: f.host.invitation.inviter, eventId: event.id, createdAt: now, event: canonical(event),
      admission: { secret: f.secret, persistent: true, epoch: 0, ...extra } })
    expect(Object.isFrozen(source)).toBe(true)
    expect(source.admission.secret).not.toBe(f.secret)
    expect('completion' in source).toBe(false)
    expect('outcome' in source).toBe(false)
    const reload = validate({ event: source.event, invitation: f.host.invitation, expectedRoomSecret: f.secret })
    expect(reload).toEqual(source)
    event.tags[0]![1] = 'changed'
    event.content = 'changed'
    source.admission.secret.fill(0)
    source.admission.relays?.splice(0)
    expect(reload.admission.secret).toEqual(f.secret)
    expect(reload.admission.relays).toEqual(extra.relays)
    reload.admission.secret.fill(0)
    expect(f.secret).toEqual(new Uint8Array(32).fill(42))
  })

  it.each(['extra', 'duplicate', 'bad-version', 'wrong-room', 'short-secret', 'bad-end', 'false-destruct',
    'bad-relays', 'extra-tag', 'missing-expiration', 'duplicate-d', 'extended-d', 'reordered-tags', 'reordered-body'])('refuses a signed unsupported body/tag shape: %s', fault => {
    const f = fixture(), event = f.invite({ endsAt: now + 100 })
    const key = hkdf(sha256, f.host.invitation.bearer, undefined, PERSISTENT_INVITATION_LABELS[0], 32)
    try {
      const body = JSON.parse(nip44.v2.decrypt(event.content, key))
      if (fault === 'extra') body.extra = true
      if (fault === 'bad-version') body.v = 4
      if (fault === 'wrong-room') body.room = '0'.repeat(64)
      if (fault === 'short-secret') body.secret = 'AA'
      if (fault === 'bad-end') body.ends = 'tomorrow'
      if (fault === 'false-destruct') body.destruct = false
      if (fault === 'bad-relays') body.relays = ['http://unsafe.example/']
      const plaintext = fault === 'duplicate' ? JSON.stringify(body).replace('"v":3', '"v":3,"v":3') :
        fault === 'reordered-body' ? JSON.stringify({ room: body.room, v: body.v, secret: body.secret, ends: body.ends }) : JSON.stringify(body)
      const tags = fault === 'extra-tag' ? [...event.tags, ['extra', 'tag']] :
        fault === 'missing-expiration' ? [event.tags[0]!] :
        fault === 'duplicate-d' ? [...event.tags, event.tags[0]!] :
        fault === 'extended-d' ? [[...event.tags[0]!, 'extra'], event.tags[1]!] :
        fault === 'reordered-tags' ? [...event.tags].reverse() : event.tags
      const bad = finalizeEvent({ ...event, tags, content: nip44.v2.encrypt(plaintext, key) }, f.host.inviterSk)
      for (const raw of [bad, canonical(bad)]) expect(() => validate({ event: raw, invitation: f.host.invitation, expectedRoomSecret: f.secret })).toThrow('signed invitation source')
    } finally { key.fill(0) }
  })

  it('refuses retirement and cannot be passed off as completed query evidence', () => {
    const f = fixture(), retirement = encodeInvitationRetirement({ ...f.host, now })
    expect(() => validate({ event: retirement, invitation: f.host.invitation, expectedRoomSecret: f.secret })).toThrow('group invitation source')
    const source = validate({ event: f.invite(), invitation: f.host.invitation, expectedRoomSecret: f.secret })
    expect(() => revalidatePersistentInvitationEvidence({ evidence: source, invitation: f.host.invitation })).toThrow()
    source.admission.secret.fill(0)
  })

  it('recomputes signatures and scope, ignoring a forged verifier cache', () => {
    const f = fixture(), event = f.invite()
    for (const bad of [{ ...event, sig: '0'.repeat(128), [verifiedSymbol]: true },
      { ...event, content: event.content + 'A', [verifiedSymbol]: true },
      finalizeEvent({ ...event }, generateSecretKey()),
      finalizeEvent({ ...event, tags: [['d', '0'.repeat(64)]] }, f.host.inviterSk)]) {
      expect(() => validate({ event: bad, invitation: f.host.invitation, expectedRoomSecret: f.secret })).toThrow('signed invitation source')
    }
    expect(() => validate({ event, invitation: { ...f.host.invitation, bearer: new Uint8Array(32).fill(1) }, expectedRoomSecret: f.secret })).toThrow('signed invitation source')
    expect(() => validate({ event, invitation: { ...f.host.invitation, persistent: false } as unknown as Parameters<typeof validate>[0]['invitation'], expectedRoomSecret: f.secret })).toThrow('persistent invitation')
  })

  it.each([undefined, null, false, '', 0, [], new Uint8Array(31), new Uint8Array(33)])('requires a valid explicit root pin: %s', pin => {
    const f = fixture()
    expect(() => validate({ event: f.invite(), invitation: f.host.invitation, expectedRoomSecret: pin as Uint8Array })).toThrow('expected room root')
    expect(f.secret).toEqual(new Uint8Array(32).fill(42))
    expect(f.host.invitation.bearer.some(byte => byte !== 0)).toBe(true)
  })

  it('refuses a different decoded room root without erasing caller buffers', () => {
    const f = fixture(), wrong = new Uint8Array(32).fill(9), bearer = f.host.invitation.bearer.slice()
    const event = f.invite(), derive = vi.spyOn(rooms, 'deriveRoom')
    try {
      expect(() => validate({ event, invitation: f.host.invitation, expectedRoomSecret: wrong })).toThrow('room root')
      expect(derive.mock.calls[0]![0]).toEqual(new Uint8Array(32))
      expect(derive.mock.results[0]!.value.roomKey).toEqual(new Uint8Array(32))
    } finally { derive.mockRestore() }
    expect(wrong).toEqual(new Uint8Array(32).fill(9))
    expect(f.host.invitation.bearer).toEqual(bearer)
  })

  it('owns its root and bearer pins before verification and erases derived room keys', () => {
    const f = fixture(), event = f.invite(), originalVerify = verifier.verifyEventUncached
    const derive = vi.spyOn(rooms, 'deriveRoom'), verify = vi.spyOn(verifier, 'verifyEventUncached')
    verify.mockImplementation(e => {
      f.secret.fill(0); f.host.invitation.bearer.fill(0); f.host.invitation.inviter = '0'.repeat(64)
      return originalVerify(e)
    })
    try {
      const source = validate({ event, invitation: f.host.invitation, expectedRoomSecret: f.secret })
      expect(source.admission.secret).toEqual(new Uint8Array(32).fill(42))
      expect(source.inviter).toBe(event.pubkey)
      expect(derive).toHaveBeenCalledTimes(1)
      expect(derive.mock.results[0]!.value.roomKey).toEqual(new Uint8Array(32))
      source.admission.secret.fill(0)
    } finally { verify.mockRestore(); derive.mockRestore() }
  })

  it.each(['trailing-space', 'order', 'extra', 'duplicate', 'invalid-json'])('refuses noncanonical stored carriers: %s', fault => {
    const f = fixture(), event = f.invite(), text = canonical(event)
    const raw = fault === 'trailing-space' ? text + ' ' : fault === 'order' ? JSON.stringify({ pubkey: event.pubkey, ...JSON.parse(text) }) :
      fault === 'extra' ? JSON.stringify({ ...JSON.parse(text), extra: true }) :
      fault === 'duplicate' ? text.replace('"kind":1463', '"kind":1463,"kind":1463') : '{'
    expect(() => validate({ event: raw, invitation: f.host.invitation, expectedRoomSecret: f.secret })).toThrow()
  })

  it.each(['x'.repeat(MAX_PERSISTENT_INVITATION_EVENT_BYTES + 1), '界'.repeat(6_000)])('refuses oversized text before parsing or signature verification', text => {
    const f = fixture(), parse = vi.spyOn(JSON, 'parse'), verify = vi.spyOn(verifier, 'verifyEventUncached')
    try {
      expect(() => validate({ event: text, invitation: f.host.invitation, expectedRoomSecret: f.secret })).toThrow('oversized')
      expect(parse).not.toHaveBeenCalled()
      expect(verify).not.toHaveBeenCalled()
    } finally { parse.mockRestore(); verify.mockRestore() }
  })

  it('bounds object byte/escaping costs and rejects executable or extra fields before verification', () => {
    const f = fixture(), event = f.invite(), getter = vi.fn(() => event.content)
    const sparse: string[][] = []; sparse.length = 1
    const badEvents = [Object.defineProperty({ ...event }, 'content', { get: getter }),
      Object.assign(Object.create({ unexpected: true }), event), { ...event, extra: true },
      { ...event, content: '界'.repeat(6_000) }, { ...event, content: '\u0000'.repeat(3_000) },
      { ...event, tags: Array(65).fill(['d', 'x']) }, { ...event, tags: sparse },
      { ...event, tags: [['d', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x']] }]
    const verify = vi.spyOn(verifier, 'verifyEventUncached')
    try {
      for (const bad of badEvents) expect(() => validate({ event: bad, invitation: f.host.invitation, expectedRoomSecret: f.secret })).toThrow()
      expect(verify).not.toHaveBeenCalled()
      expect(getter).not.toHaveBeenCalled()
    } finally { verify.mockRestore() }
  })
})
