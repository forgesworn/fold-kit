import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { randomBytes } from '@noble/hashes/utils'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure'
import { MAX_EPOCH, type RoomEpoch } from './epoch.js'
import { deriveInvitationId, encodeInvitationRetirement, decodeInvitationRetirementNotice, retirementError } from './invitation.js'
import { KINDS } from './kinds.js'
import { deriveRoom } from './room.js'
import { assertCompleteStoredQuery, type StoredEventQuery } from './stored-query.js'
import { verifyEventUncached } from './verify.js'

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }
export interface EpochInvitation { v: 4; bearer: Uint8Array; inviter: string }
export interface EpochAdmission {
  roomId: string
  authority: string
  current: RoomEpoch
  app?: Record<string, JsonValue>
}

export const EPOCH_INVITATION_KEY_INFO = 'kithmoot/v4/group-invitation-key'
export const EPOCH_INVITATION_LABELS = [EPOCH_INVITATION_KEY_INFO] as const
export const MAX_EPOCH_INVITATION_APP_BYTES = 256
const MAX_CONTENT_LENGTH = 4096
const MAX_CANDIDATES = 256
const HEX64 = /^[0-9a-f]{64}$/

function checkInvitation(invitation: EpochInvitation): void {
  if (!invitation || invitation.v !== 4 || !(invitation.bearer instanceof Uint8Array) ||
      invitation.bearer.length !== 32 || !HEX64.test(invitation.inviter)) throw new Error('invalid epoch invitation')
}

function requireRoomId(roomId: string): string {
  if (typeof roomId !== 'string' || !HEX64.test(roomId)) throw new Error('invalid room id')
  return roomId
}

function requireEpoch(current: RoomEpoch): RoomEpoch {
  if (!current || !Number.isSafeInteger(current.epoch) || current.epoch < 0 || current.epoch > MAX_EPOCH ||
      !(current.secret instanceof Uint8Array) || current.secret.length !== 32) throw new Error('invalid current epoch')
  return current
}

function ownKeys(value: object): string[] {
  const keys = Reflect.ownKeys(value)
  if (keys.some((key) => typeof key === 'symbol')) throw new Error('app has symbol keys')
  return keys as string[]
}

/** Reject non-JSON encoder inputs rather than letting JSON.stringify silently omit them. */
function copyJson(value: unknown, seen: WeakSet<object>, depth: number, count: { n: number }): JsonValue {
  if (++count.n > 512 || depth > 16) throw new Error('app JSON is too deep or large')
  if (value === null || typeof value === 'boolean') return value
  if (typeof value === 'string') {
    if (value.length > MAX_EPOCH_INVITATION_APP_BYTES) throw new Error('app string exceeds byte budget')
    return value
  }
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value !== 'object') throw new Error('app is not strict JSON data')
  if (seen.has(value)) throw new Error('app contains a cycle')
  seen.add(value)
  if (Array.isArray(value)) {
    const keys = ownKeys(value)
    if (keys.length !== value.length + 1 || keys.some((key) => key !== 'length' &&
        (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))) {
      throw new Error('app array has non-JSON properties')
    }
    const out: JsonValue[] = []
    for (let i = 0; i < value.length; i++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, i)
      if (!descriptor) throw new Error('app has a sparse array')
      if (!descriptor.enumerable || !('value' in descriptor)) throw new Error('app contains an accessor')
      out.push(copyJson(descriptor.value, seen, depth + 1, count))
    }
    seen.delete(value)
    return out
  }
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new Error('app contains a non-plain object')
  }
  const out: Record<string, JsonValue> = {}
  for (const key of ownKeys(value)) {
    if (key.length > MAX_EPOCH_INVITATION_APP_BYTES) throw new Error('app key exceeds byte budget')
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) throw new Error('app contains an accessor')
    Object.defineProperty(out, key, { value: copyJson(descriptor.value, seen, depth + 1, count),
      enumerable: true, configurable: true, writable: true })
  }
  seen.delete(value)
  return out
}

function strictApp(value: unknown): Record<string, JsonValue> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('app must be a JSON object')
  const copied = copyJson(value, new WeakSet(), 0, { n: 0 }) as Record<string, JsonValue>
  if (new TextEncoder().encode(JSON.stringify(copied)).length > MAX_EPOCH_INVITATION_APP_BYTES) {
    throw new Error('app JSON exceeds 256 UTF-8 bytes')
  }
  return copied
}

function welcomeKey(invitation: EpochInvitation): Uint8Array {
  checkInvitation(invitation)
  return hkdf(sha256, invitation.bearer, undefined, EPOCH_INVITATION_KEY_INFO, 32)
}

export function encodeEpochInvitation(opts: {
  invitation: EpochInvitation; authoritySk: Uint8Array; roomId: string
  current: RoomEpoch; app?: Record<string, JsonValue>; now: number
}): Event {
  checkInvitation(opts.invitation)
  if (!(opts.authoritySk instanceof Uint8Array) || opts.authoritySk.length !== 32 ||
      getPublicKey(opts.authoritySk) !== opts.invitation.inviter) throw new Error('authority key does not match invitation')
  const roomId = requireRoomId(opts.roomId)
  const current = requireEpoch(opts.current)
  if (current.epoch === 0 && deriveRoom(current.secret).roomId !== roomId) throw new Error('epoch zero secret does not bind room id')
  if (!Number.isSafeInteger(opts.now) || opts.now < 0) throw new Error('invalid invitation time')
  const app = opts.app === undefined ? undefined : strictApp(opts.app)
  const body = { v: 4, room: roomId, epoch: current.epoch, secret: base64urlnopad.encode(current.secret),
    ...(app === undefined ? {} : { app }) }
  return finalizeEvent({ kind: KINDS.GROUP_INVITATION, created_at: opts.now,
    tags: [['d', deriveInvitationId(opts.invitation)]],
    content: nip44.v2.encrypt(JSON.stringify(body), welcomeKey(opts.invitation)) }, opts.authoritySk)
}

/** Malformed, wrong-bearer, cross-version or unauthorised wire events return null. */
export function decodeEpochInvitation(event: Event, invitation: EpochInvitation): EpochAdmission | null {
  try {
    checkInvitation(invitation)
    if (!event || event.kind !== KINDS.GROUP_INVITATION || event.pubkey !== invitation.inviter ||
        typeof event.id !== 'string' || !HEX64.test(event.id) ||
        typeof event.sig !== 'string' || !/^[0-9a-f]{128}$/.test(event.sig) ||
        !Number.isSafeInteger(event.created_at) || event.created_at < 0 ||
        typeof event.content !== 'string' || event.content.length > MAX_CONTENT_LENGTH ||
        !Array.isArray(event.tags) || event.tags.length !== 1 || !Array.isArray(event.tags[0]) ||
        event.tags[0]!.length !== 2 || event.tags[0]![0] !== 'd' ||
        event.tags[0]![1] !== deriveInvitationId(invitation)) return null
    if (!verifyEventUncached(event)) return null
    const body: unknown = JSON.parse(nip44.v2.decrypt(event.content, welcomeKey(invitation)))
    if (!body || typeof body !== 'object' || Array.isArray(body)) return null
    const fields = body as Record<string, unknown>
    if (fields.v !== 4 || Object.keys(fields).some((key) => !['v', 'room', 'epoch', 'secret', 'app'].includes(key)) ||
        typeof fields.room !== 'string' || !HEX64.test(fields.room) ||
        !Number.isSafeInteger(fields.epoch) || (fields.epoch as number) < 0 || (fields.epoch as number) > MAX_EPOCH ||
        typeof fields.secret !== 'string') return null
    const secret = base64urlnopad.decode(fields.secret)
    if (secret.length !== 32 || base64urlnopad.encode(secret) !== fields.secret) return null
    if (fields.epoch === 0 && deriveRoom(secret).roomId !== fields.room) return null
    const app = Object.hasOwn(fields, 'app') ? strictApp(fields.app) : undefined
    return { roomId: fields.room, authority: invitation.inviter,
      current: { epoch: fields.epoch as number, secret }, ...(app === undefined ? {} : { app }) }
  } catch { return null }
}

export function prepareEpochInvitation(opts: {
  authoritySk: Uint8Array; roomId: string; current: RoomEpoch
  app?: Record<string, JsonValue>; previous?: EpochInvitation; now: number
}): { invitation: EpochInvitation; welcome: Event; retirement?: Event } {
  if (!(opts.authoritySk instanceof Uint8Array) || opts.authoritySk.length !== 32) throw new Error('invalid authority key')
  const inviter = getPublicKey(opts.authoritySk)
  if (opts.previous) {
    checkInvitation(opts.previous)
    if (opts.previous.inviter !== inviter) throw new Error('previous invitation has another authority')
  }
  const invitation: EpochInvitation = { v: 4, bearer: randomBytes(32), inviter }
  if (opts.previous && invitation.bearer.every((byte, index) => byte === opts.previous!.bearer[index])) {
    throw new Error('fresh invitation bearer matched the retired bearer')
  }
  const welcome = encodeEpochInvitation({ ...opts, invitation })
  const retirement = opts.previous ? encodeInvitationRetirement({ invitation: opts.previous,
    inviterSk: opts.authoritySk, now: opts.now }) : undefined
  return { invitation, welcome, ...(retirement === undefined ? {} : { retirement }) }
}

function semanticJson(value: unknown): string {
  if (value === undefined) return 'undefined'
  if (Array.isArray(value)) return `[${value.map(semanticJson).join(',')}]`
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${semanticJson((value as Record<string, unknown>)[key])}`).join(',')}}`
  return JSON.stringify(value)
}

function sameAdmission(a: EpochAdmission, b: EpochAdmission): boolean {
  return a.roomId === b.roomId && a.authority === b.authority && a.current.epoch === b.current.epoch &&
    a.current.secret.every((byte, index) => byte === b.current.secret[index]) &&
    semanticJson(a.app) === semanticJson(b.app)
}

/** A single stored query for welcome and retirement; no real EOSE means no admission. */
export async function requestEpochAdmission(opts: {
  invitation: EpochInvitation; query: StoredEventQuery; signal?: AbortSignal
}): Promise<EpochAdmission> {
  checkInvitation(opts.invitation)
  if (opts.signal?.aborted) throw new Error('epoch admission cancelled')
  let admission: EpochAdmission | undefined
  let retirement: { ended: boolean } | undefined
  let conflict = false
  let overflow = false
  let count = 0
  let complete = false
  const result = await opts.query([{ kinds: [KINDS.GROUP_INVITATION, KINDS.INVITATION_RETIREMENT],
    authors: [opts.invitation.inviter], '#d': [deriveInvitationId(opts.invitation)] }], (event) => {
    if (complete || overflow) return
    if (++count > MAX_CANDIDATES) { overflow = true; return }
    // The legacy retirement verifier hashes before checking its content. Bound the
    // exact v1 tombstone shape here before handing an untrusted relay event to it.
    const retirementShaped = event?.kind === KINDS.INVITATION_RETIREMENT &&
      typeof event.id === 'string' && HEX64.test(event.id) &&
      typeof event.sig === 'string' && /^[0-9a-f]{128}$/.test(event.sig) &&
      typeof event.content === 'string' && event.content.length <= 128 &&
      Array.isArray(event.tags) && event.tags.length === 1 && Array.isArray(event.tags[0]) &&
      event.tags[0]!.length === 2 && event.tags[0]![0] === 'd' &&
      event.tags[0]![1] === deriveInvitationId(opts.invitation)
    const retired = retirementShaped ? decodeInvitationRetirementNotice(event, opts.invitation) : undefined
    if (retired) { retirement = retired; return }
    const decoded = decodeEpochInvitation(event, opts.invitation)
    if (!decoded) return
    if (admission && !sameAdmission(admission, decoded)) conflict = true
    else admission = decoded
  }, opts.signal)
  complete = true
  assertCompleteStoredQuery(result)
  if (opts.signal?.aborted) throw new Error('epoch admission cancelled')
  if (overflow) throw new Error('stored epoch invitation result is incomplete')
  if (retirement) throw retirementError(retirement)
  if (conflict) throw new Error('epoch invitation has conflicting valid welcomes')
  if (!admission) throw new Error('epoch invitation is not available on queried relays')
  return { ...admission, current: { epoch: admission.current.epoch, secret: admission.current.secret.slice() } }
}
