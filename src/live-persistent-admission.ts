import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure'
import { deriveInvitationId, type RoomInvitation } from './invitation.js'
import { decodePersistentInvitation, type PersistentRoomAdmission } from './persistent-invitation.js'
import { deriveRoom } from './room.js'
import { verifyEventUncached } from './verify.js'
import { KINDS } from './kinds.js'

const REQUEST_KEY = 'kithmoot/v1/persistent-live/request-key'
const PROFILE = 'persistent-live'
const HEX = /^[0-9a-f]{64}$/
const SIG = /^[0-9a-f]{128}$/
const utf8 = new TextEncoder()
const text = new TextDecoder('utf-8', { fatal: true })
export const LIVE_PERSISTENT_REQUEST_SECONDS = 90
export const LIVE_PERSISTENT_RESPONSE_SECONDS = 30
const SKEW = 5

export interface LivePersistentContext {
  invitation: RoomInvitation
  /** From the separate routing descriptor; authenticated again in the answer. */
  roomId: string
}

export interface LivePersistentRequest {
  requestId: string
  requester: string
  createdAt: number
  expiresAt: number
}

/** Capability evidence only. The caller must still perform epoch admission. */
export interface LivePersistentAnswer {
  admission: PersistentRoomAdmission
  epochHint: number
  requestId: string
  expiresAt: number
}

function check(ok: unknown): asserts ok {
  if (!ok) throw new Error('invalid live persistent admission')
}

function integer(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0
}

function clock(now: number): void {
  check(integer(now) && now <= Number.MAX_SAFE_INTEGER - LIVE_PERSISTENT_REQUEST_SECONDS)
}

function context(opts: LivePersistentContext): void {
  check(opts.invitation.persistent === true && opts.invitation.bearer.length === 32)
  check(HEX.test(opts.invitation.inviter) && HEX.test(opts.roomId))
}

function fields(raw: unknown, names: readonly string[]): asserts raw is Record<string, unknown> {
  check(typeof raw === 'object' && raw !== null && !Array.isArray(raw))
  const keys = Object.keys(raw)
  check(keys.length === names.length && keys.every(k => names.includes(k)))
}

/** Minified JSON also rejects duplicate fields and ambiguous number spellings. */
function body(raw: string, names: readonly string[]): Record<string, unknown> {
  const parsed: unknown = JSON.parse(raw)
  fields(parsed, names)
  check(JSON.stringify(parsed) === raw)
  return parsed
}

function key(invitation: RoomInvitation): Uint8Array {
  return hkdf(sha256, invitation.bearer, undefined, REQUEST_KEY, 32)
}

function wire(event: Event): Event {
  return { id: event.id, pubkey: event.pubkey, created_at: event.created_at,
    kind: event.kind, tags: event.tags, content: event.content, sig: event.sig }
}

/** Bound every field before serialising or verifying an attacker-supplied object. */
function eventBounds(raw: unknown, contentLimit: number, byteLimit: number, tagsLimit: number): asserts raw is Event {
  fields(raw, ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'])
  check(typeof raw.id === 'string' && HEX.test(raw.id) && typeof raw.pubkey === 'string' && HEX.test(raw.pubkey))
  check(typeof raw.sig === 'string' && SIG.test(raw.sig) && integer(raw.kind) && integer(raw.created_at))
  check(typeof raw.content === 'string' && raw.content.length <= contentLimit)
  check(Array.isArray(raw.tags) && raw.tags.length <= tagsLimit)
  for (const tag of raw.tags) {
    check(Array.isArray(tag) && tag.length <= 4 && tag.every(v => typeof v === 'string' && v.length <= 256))
  }
  check(utf8.encode(JSON.stringify(raw)).length <= byteLimit)
}

/** For raw input boundaries: bound bytes before parsing, retain exact fields,
 * and reject duplicate JSON keys before a general event reader can discard them. */
export function parseLivePersistentEvent(json: string, request: boolean): Event | null {
  try {
    const max = request ? 4096 : 20480
    check(typeof json === 'string' && json.length <= max && utf8.encode(json).length <= max)
    const raw: unknown = JSON.parse(json)
    check(JSON.stringify(raw) === json)
    eventBounds(raw, request ? 2048 : 16384, max, 3)
    return raw
  } catch { return null }
}

function envelope(event: Event, opts: LivePersistentContext, kind: number, recipient: string, now: number): number {
  context(opts)
  clock(now)
  const request = kind === KINDS.INVITATION_REQUEST
  eventBounds(event, request ? 2048 : 16384, request ? 4096 : 20480, 3)
  check(event.kind === kind && event.created_at <= now + SKEW)
  check(event.tags.length === 3 && event.tags.every(t => t.length === 2))
  const tag = (name: string): string => {
    const matches = event.tags.filter(t => t[0] === name)
    check(matches.length === 1)
    return matches[0]![1]!
  }
  check(tag('d') === deriveInvitationId(opts.invitation) && tag('p') === recipient)
  const expiresAt = Number(tag('expiration'))
  check(integer(expiresAt) && String(expiresAt) === tag('expiration') && expiresAt > now)
  check(verifyEventUncached(event))
  return expiresAt
}

/** Routing metadata only; never advertise the invitation bearer. */
export function encodeLivePersistentDescriptor(opts: LivePersistentContext): string {
  context(opts)
  return base64urlnopad.encode(utf8.encode(JSON.stringify({ v: 1, room: opts.roomId,
    invitation: deriveInvitationId(opts.invitation), inviter: opts.invitation.inviter })))
}

export function decodeLivePersistentDescriptor(encoded: string, invitation: RoomInvitation): LivePersistentContext | null {
  try {
    check(typeof encoded === 'string' && encoded.length <= 512)
    const bytes = base64urlnopad.decode(encoded)
    check(bytes.length <= 384 && base64urlnopad.encode(bytes) === encoded)
    const raw = body(text.decode(bytes), ['v', 'room', 'invitation', 'inviter'])
    check(raw.v === 1 && typeof raw.room === 'string')
    const opts = { invitation, roomId: raw.room }
    context(opts)
    check(raw.invitation === deriveInvitationId(invitation) && raw.inviter === invitation.inviter)
    return opts
  } catch { return null }
}

export function encodeLivePersistentRequest(opts: LivePersistentContext & { requesterSk: Uint8Array; now: number }): Event {
  context(opts)
  clock(opts.now)
  return finalizeEvent({ kind: KINDS.INVITATION_REQUEST, created_at: opts.now,
    tags: [['d', deriveInvitationId(opts.invitation)], ['p', opts.invitation.inviter],
      ['expiration', String(opts.now + LIVE_PERSISTENT_REQUEST_SECONDS)]],
    content: nip44.v2.encrypt(JSON.stringify({ v: 1, profile: PROFILE, room: opts.roomId,
      requester: getPublicKey(opts.requesterSk) }), key(opts.invitation)),
  }, opts.requesterSk)
}

export function decodeLivePersistentRequest(event: Event, opts: LivePersistentContext & { now: number }): LivePersistentRequest | null {
  try {
    const expiresAt = envelope(event, opts, KINDS.INVITATION_REQUEST, opts.invitation.inviter, opts.now)
    check(expiresAt === event.created_at + LIVE_PERSISTENT_REQUEST_SECONDS)
    const raw = body(nip44.v2.decrypt(event.content, key(opts.invitation)), ['v', 'profile', 'room', 'requester'])
    check(raw.v === 1 && raw.profile === PROFILE && raw.room === opts.roomId && raw.requester === event.pubkey)
    return { requestId: event.id, requester: event.pubkey, createdAt: event.created_at, expiresAt }
  } catch { return null }
}

function invitationOf(event: unknown, opts: LivePersistentContext, now: number, responseAt: number): PersistentRoomAdmission {
  eventBounds(event, 6144, 8192, 8)
  check(event.created_at <= Math.min(now, responseAt) + SKEW)
  const admission = decodePersistentInvitation(event, opts.invitation)
  check(admission !== null && deriveRoom(admission.secret).roomId === opts.roomId)
  check(admission.endsAt === undefined || admission.endsAt > now)
  return admission
}

/** Codec only: callers must hold the durable lifecycle lock through handoff.
 * This function cannot prove that the root's invitation is active. */
export function encodeLivePersistentAnswer(opts: LivePersistentContext & {
  request: Event; invitationEvent: Event; inviterSk: Uint8Array; epoch: number; now: number
}): Event {
  const request = decodeLivePersistentRequest(opts.request, opts)
  check(request !== null && integer(opts.epoch) && getPublicKey(opts.inviterSk) === opts.invitation.inviter)
  check(opts.now >= request.createdAt - SKEW)
  invitationOf(opts.invitationEvent, opts, opts.now, opts.now)
  const event = finalizeEvent({ kind: KINDS.INVITATION_GRANT, created_at: opts.now,
    tags: [['d', deriveInvitationId(opts.invitation)], ['p', request.requester],
      ['expiration', String(Math.min(request.expiresAt, opts.now + LIVE_PERSISTENT_RESPONSE_SECONDS))]],
    content: nip44.v2.encrypt(JSON.stringify({ v: 1, profile: PROFILE, request: request.requestId,
      room: opts.roomId, epoch: opts.epoch, invitation: wire(opts.invitationEvent) }),
    nip44.v2.utils.getConversationKey(opts.inviterSk, request.requester)),
  }, opts.inviterSk)
  eventBounds(event, 16384, 20480, 3)
  return event
}

/** Stateless proof reader. The request owner consumes a result at most once. */
export function decodeLivePersistentAnswer(event: Event, opts: LivePersistentContext & {
  request: Event; requesterSk: Uint8Array; now: number
}): LivePersistentAnswer | null {
  try {
    const request = decodeLivePersistentRequest(opts.request, opts)
    check(request !== null && getPublicKey(opts.requesterSk) === request.requester)
    const expiresAt = envelope(event, opts, KINDS.INVITATION_GRANT, request.requester, opts.now)
    check(event.pubkey === opts.invitation.inviter && event.created_at >= request.createdAt - SKEW)
    check(expiresAt === Math.min(request.expiresAt, event.created_at + LIVE_PERSISTENT_RESPONSE_SECONDS))
    const raw = body(nip44.v2.decrypt(event.content,
      nip44.v2.utils.getConversationKey(opts.requesterSk, opts.invitation.inviter)),
    ['v', 'profile', 'request', 'room', 'epoch', 'invitation'])
    check(raw.v === 1 && raw.profile === PROFILE && raw.request === request.requestId && raw.room === opts.roomId && integer(raw.epoch))
    const admission = invitationOf(raw.invitation, opts, opts.now, event.created_at)
    return { admission, epochHint: raw.epoch, requestId: request.requestId, expiresAt }
  } catch { return null }
}

export const LIVE_PERSISTENT_ADMISSION_LABELS = [REQUEST_KEY] as const
