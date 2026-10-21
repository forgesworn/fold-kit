import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { verifiedSymbol, type Event } from 'nostr-tools/pure'
import { deriveInvitationId, roomInvitation, decodeInvitationRetirementNotice, type RoomInvitation } from './invitation.js'
import { PERSISTENT_INVITATION_LABELS, type PersistentRoomAdmission } from './persistent-invitation.js'
import { isRoomEnds } from './expiration.js'
import { isInvitationRelays } from './invitation-relays.js'
import { isInvitationStorage } from './invitation-storage.js'
import { deriveRoom } from './room.js'
import { KINDS } from './kinds.js'
import { verifyEventUncached } from './verify.js'
import type { RelayTransport } from './transport.js'

export const MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS = 64
export const MAX_PERSISTENT_INVITATION_EVENT_BYTES = 16_384
export const MAX_PERSISTENT_INVITATION_EVIDENCE_BYTES = 262_144
/** Raw deliveries one query reads, counted before anything is parsed: every
 * relay's copy of every event, repeats, other authors and junk alike. It bounds
 * parse work only. It is eight times the retained-event limit, so 64 events
 * from each of eight relays still fit. Past it the query fails closed, because
 * an event that could matter may be among those it did not read. */
export const MAX_PERSISTENT_INVITATION_EVIDENCE_DELIVERIES = 512
/** Signature checks one query makes. Only an event that is in scope, well
 * formed and not already held or refused costs one, so a repeat costs none. It
 * is twice the retained-event limit: room for 64 retained events and 64 more
 * in-scope events that fail (forged, or signed but not a supported body).
 * Beyond it the query fails closed rather than skip an unchecked event. */
export const MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS = 128

/** Protected, local observation metadata. EOSE is NOT evidence of relay
 * completeness, current membership or global absence of retirement.
 * `events` are canonical allowlisted Event carriers, not original wire JSON. */
export interface PersistentInvitationEvidence {
  readonly version: 1
  readonly invitationId: string
  readonly inviter: string
  readonly completion: 'eose'
  readonly eventIds: readonly string[]
  readonly events: readonly string[]
}

export interface PersistentInvitationContributors {
  readonly room: readonly string[]
  readonly ends: readonly string[]
  readonly destruct: readonly string[]
  readonly relays: readonly string[]
  /** The copies whose list stood. Present exactly when a copy names storage,
   *  so a room with none has the same contributors as 0.13.0 wrote. */
  readonly storage?: readonly string[]
}

export type PersistentInvitationEvidenceOutcome = {
  readonly status: 'admitted'
  /** A fresh owned secret buffer; caller must erase it when finished. */
  readonly admission: PersistentRoomAdmission
  readonly contributors: PersistentInvitationContributors
} | {
  readonly status: 'held'
  readonly reason: 'unavailable' | 'retired' | 'conflicting-rooms' | 'conflicting-relays' | 'conflicting-storage' | 'wrong-room'
  readonly retirementEventIds: readonly string[]
}

export interface PersistentInvitationEvidenceResult {
  readonly evidence: PersistentInvitationEvidence
  readonly outcome: PersistentInvitationEvidenceOutcome
}

/** One authenticated group event, without an observation/completion claim.
 * This proves its signed fields only, not publication, current membership,
 * latest selection or absence of retirement. */
export interface PersistentInvitationSource {
  readonly version: 1
  readonly invitationId: string
  readonly inviter: string
  readonly eventId: string
  readonly createdAt: number
  /** Exact canonical carrier bytes to retain and reuse for publication. */
  readonly event: string
  /** Fresh owned decoded fields; caller must erase the secret after use. */
  readonly admission: PersistentRoomAdmission
}

/** Incomplete observations are bounded diagnostic custody only. They are
 * never accepted by revalidatePersistentInvitationEvidence. */
export class PersistentInvitationEvidenceQueryError extends Error {
  readonly observation: Omit<PersistentInvitationEvidence, 'completion'> & { readonly completion: 'incomplete' }
  constructor(message: string, observation: PersistentInvitationEvidenceQueryError['observation']) {
    super(message)
    this.name = 'PersistentInvitationEvidenceQueryError'
    this.observation = observation
  }
}

const fields = ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'] as const
const utf8 = new TextEncoder()
const hex32 = /^[0-9a-f]{64}$/
const hex64 = /^[0-9a-f]{128}$/

/** JSON string byte cost including escaping, without serialising content. */
function jsonStringBytes(value: string): number {
  let bytes = 2
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i)
    if (c === 34 || c === 92) bytes += 2
    else if (c < 32) bytes += [8, 9, 10, 12, 13].includes(c) ? 2 : 6
    else if (c < 128) bytes++
    else if (c < 2048) bytes += 2
    else if (c >= 0xd800 && c <= 0xdbff && value.charCodeAt(i + 1) >= 0xdc00 && value.charCodeAt(i + 1) <= 0xdfff) { bytes += 4; i++ }
    else if (c >= 0xd800 && c <= 0xdfff) bytes += 6
    else bytes += 3
    if (bytes > MAX_PERSISTENT_INVITATION_EVENT_BYTES) throw new Error('oversized evidence event')
  }
  return bytes
}

function dataRecord(raw: unknown, allowed: readonly string[], ignoredSymbol?: symbol): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) throw new Error('invalid evidence record')
  const descriptors = Object.getOwnPropertyDescriptors(raw)
  for (const key of Reflect.ownKeys(descriptors)) {
    if ((typeof key === 'symbol' ? key !== ignoredSymbol : !allowed.includes(key)) || !('value' in descriptors[key as string])) throw new Error('invalid evidence field')
  }
  const result: Record<string, unknown> = Object.create(null)
  for (const key of allowed) if (descriptors[key]) result[key] = descriptors[key]!.value
  return result
}

function dataArray(raw: unknown, limit: number): unknown[] {
  if (!Array.isArray(raw) || Object.getPrototypeOf(raw) !== Array.prototype || raw.length > limit) throw new Error('invalid evidence array')
  const descriptors = Object.getOwnPropertyDescriptors(raw)
  if (Reflect.ownKeys(descriptors).length !== raw.length + 1) throw new Error('invalid evidence array fields')
  const values: unknown[] = []
  for (let i = 0; i < raw.length; i++) {
    if (!descriptors[i] || !('value' in descriptors[i]!)) throw new Error('invalid evidence array item')
    values.push(descriptors[i]!.value)
  }
  return values
}

/** Fresh carrier copy, with no trusted verification-cache symbol. Bounds
 * precede copying or serialising potentially large strings/tag arrays. */
function carrier(raw: unknown): { event: Event; canonical: string; bytes: number } {
  const d = dataRecord(raw, fields, verifiedSymbol)
  if (Object.keys(d).length !== fields.length || typeof d.id !== 'string' || !hex32.test(d.id) ||
      typeof d.pubkey !== 'string' || !hex32.test(d.pubkey) || typeof d.sig !== 'string' || !hex64.test(d.sig) ||
      !Number.isSafeInteger(d.created_at) || (d.created_at as number) < 0 || !Number.isSafeInteger(d.kind) || (d.kind as number) < 0 ||
      typeof d.content !== 'string' || d.content.length > MAX_PERSISTENT_INVITATION_EVENT_BYTES) throw new Error('invalid or oversized evidence event')
  let bytes = '{"id":,"pubkey":,"created_at":,"kind":,"tags":,"content":,"sig":}'.length +
    String(d.created_at).length + String(d.kind).length + jsonStringBytes(d.id) + jsonStringBytes(d.pubkey) + jsonStringBytes(d.sig) + jsonStringBytes(d.content)
  if (bytes > MAX_PERSISTENT_INVITATION_EVENT_BYTES) throw new Error('oversized evidence event')
  const outer = dataArray(d.tags, 64)
  bytes += 2 + Math.max(0, outer.length - 1)
  const tags = outer.map(tag => {
    const inner = dataArray(tag, 8)
    bytes += 2 + Math.max(0, inner.length - 1)
    return inner.map(value => {
      if (typeof value !== 'string' || value.length > MAX_PERSISTENT_INVITATION_EVENT_BYTES) throw new Error('invalid or oversized evidence tag')
      bytes += jsonStringBytes(value)
      if (bytes > MAX_PERSISTENT_INVITATION_EVENT_BYTES) throw new Error('oversized evidence event')
      return value
    })
  })
  if (bytes > MAX_PERSISTENT_INVITATION_EVENT_BYTES) throw new Error('oversized evidence event')
  const event: Event = { id: d.id, pubkey: d.pubkey, created_at: d.created_at as number, kind: d.kind as number, tags, content: d.content, sig: d.sig }
  const canonical = JSON.stringify(event)
  return { event, canonical, bytes }
}

function copyInvitation(invitation: RoomInvitation): RoomInvitation {
  if (!invitation.persistent || !(invitation.bearer instanceof Uint8Array) || invitation.bearer.length !== 32 || !hex32.test(invitation.inviter)) throw new Error('a canonical persistent invitation is required')
  return roomInvitation(invitation.bearer.slice(), invitation.inviter, true)
}

function roomId(secret: Uint8Array): string {
  const room = deriveRoom(secret)
  room.roomKey.fill(0)
  return room.roomId
}

/** The cheap, unsigned part of scope: the authority, a source kind and exactly
 * one two-element `d` tag naming this invitation. No crypto. */
function inAuthorityScope(event: Event, inviter: string, invitationId: string): boolean {
  if (event.pubkey !== inviter || (event.kind !== KINDS.GROUP_INVITATION && event.kind !== KINDS.INVITATION_RETIREMENT)) return false
  const d = event.tags.filter(tag => tag[0] === 'd')
  return d.length === 1 && d[0]!.length === 2 && d[0]![1] === invitationId
}

function signedScope(event: Event, invitation: RoomInvitation): boolean {
  return inAuthorityScope(event, invitation.inviter, deriveInvitationId(invitation)) && verifyEventUncached(event)
}

/** Strict evidence path accepts exactly the bodies/tags of supported writers;
 * permissive legacy decoding and its public request remain unchanged. */
function decodeEvidenceEvent(event: Event, invitation: RoomInvitation): PersistentRoomAdmission | 'retired' | null {
  if (!signedScope(event, invitation)) return null
  if (event.kind === KINDS.INVITATION_RETIREMENT) {
    const notice = decodeInvitationRetirementNotice(event, invitation)
    return notice ? 'retired' : null
  }
  let accepted = false, secret: Uint8Array | undefined
  const key = hkdf(sha256, invitation.bearer, undefined, PERSISTENT_INVITATION_LABELS[0], 32)
  try {
    const plaintext = nip44.v2.decrypt(event.content, key)
    const body = dataRecord(JSON.parse(plaintext), ['v', 'room', 'secret', 'ends', 'destruct', 'relays', 'storage'])
    if (body.v !== 3 || typeof body.secret !== 'string' || (body.ends !== undefined && !isRoomEnds(body.ends)) ||
        (body.destruct !== undefined && body.destruct !== true) || (body.relays !== undefined && !isInvitationRelays(body.relays)) ||
        (body.storage !== undefined && !isInvitationStorage(body.storage))) return null
    secret = base64urlnopad.decode(body.secret)
    if (secret.length !== 32 || body.room !== roomId(secret)) return null
    const decoded: PersistentRoomAdmission = { secret, persistent: true, epoch: 0,
      ...(body.ends === undefined ? {} : { endsAt: body.ends as number }), ...(body.destruct ? { destruct: true as const } : {}),
      ...(body.relays === undefined ? {} : { relays: [...body.relays as string[]] }),
      ...(body.storage === undefined ? {} : { storage: [...body.storage as string[]], storageAt: event.created_at }) }
    const expected = JSON.stringify({ v: 3, room: body.room, secret: base64urlnopad.encode(secret),
      ...(decoded.endsAt === undefined ? {} : { ends: decoded.endsAt }), ...(decoded.destruct ? { destruct: true } : {}),
      ...(decoded.relays === undefined ? {} : { relays: decoded.relays }), ...(decoded.storage === undefined ? {} : { storage: decoded.storage }) })
    const tags = decoded.endsAt === undefined ? [['d', deriveInvitationId(invitation)]] : [['d', deriveInvitationId(invitation)], ['expiration', String(decoded.endsAt)]]
    accepted = plaintext === expected && JSON.stringify(event.tags) === JSON.stringify(tags)
    return accepted ? decoded : null
  } catch { return null } finally {
    key.fill(0)
    if (!accepted) secret?.fill(0)
  }
}

/** Validate an actual encoder Event or its exact retained canonical carrier.
 * A room-root pin is mandatory. No signing, query, storage or publication is
 * performed. In particular, this cannot manufacture one-event EOSE evidence. */
export function revalidatePersistentInvitationSource(opts: {
  event: unknown
  invitation: RoomInvitation
  expectedRoomSecret: Uint8Array
}): PersistentInvitationSource {
  const invitation = copyInvitation(opts.invitation)
  let root: Uint8Array | undefined, admission: PersistentRoomAdmission | undefined
  let transferred = false
  try {
    const expected = opts.expectedRoomSecret
    if (!(expected instanceof Uint8Array) || expected.length !== 32) throw new Error('invalid expected room root')
    root = expected.slice()
    const raw = opts.event
    let c: ReturnType<typeof carrier>
    if (typeof raw === 'string') {
      if (raw.length > MAX_PERSISTENT_INVITATION_EVENT_BYTES || utf8.encode(raw).length > MAX_PERSISTENT_INVITATION_EVENT_BYTES) throw new Error('oversized invitation source carrier')
      c = carrier(JSON.parse(raw))
      if (c.canonical !== raw) throw new Error('noncanonical invitation source carrier')
    } else c = carrier(raw)
    if (c.event.kind !== KINDS.GROUP_INVITATION) throw new Error('a group invitation source is required')
    const decoded = decodeEvidenceEvent(c.event, invitation)
    if (!decoded || decoded === 'retired') throw new Error('invalid signed invitation source')
    admission = decoded
    if (!admission.secret.every((byte, i) => byte === root![i])) throw new Error('wrong invitation source room root')
    const result: PersistentInvitationSource = Object.freeze({ version: 1 as const,
      invitationId: deriveInvitationId(invitation), inviter: invitation.inviter,
      eventId: c.event.id, createdAt: c.event.created_at, event: c.canonical, admission })
    transferred = true
    return result
  } finally {
    if (!transferred) admission?.secret.fill(0)
    root?.fill(0)
    invitation.bearer.fill(0)
  }
}

function observation(invitation: RoomInvitation, events: ReadonlyMap<string, string>, completion: 'eose'): PersistentInvitationEvidence
function observation(invitation: RoomInvitation, events: ReadonlyMap<string, string>, completion: 'incomplete'): PersistentInvitationEvidenceQueryError['observation']
function observation(invitation: RoomInvitation, events: ReadonlyMap<string, string>, completion: 'eose' | 'incomplete') {
  const ids = [...events.keys()].sort()
  return Object.freeze({ version: 1 as const, invitationId: deriveInvitationId(invitation), inviter: invitation.inviter, completion,
    eventIds: Object.freeze(ids), events: Object.freeze(ids.map(id => events.get(id)!)) })
}

/** Reverify all carriers and reproduce selection from protected evidence.
 * Optional expectedRoomSecret binds an existing physical room to its exact
 * root, not merely the invitation's current or historical room label. */
export function revalidatePersistentInvitationEvidence(opts: {
  evidence: unknown
  invitation: RoomInvitation
  expectedRoomSecret?: Uint8Array
}): PersistentInvitationEvidenceResult {
  const invitation = copyInvitation(opts.invitation)
  const decoded: Array<{ event: Event; admission: PersistentRoomAdmission }> = []
  try {
    if (opts.expectedRoomSecret !== undefined && (!(opts.expectedRoomSecret instanceof Uint8Array) || opts.expectedRoomSecret.length !== 32)) throw new Error('invalid expected room root')
    const d = dataRecord(opts.evidence, ['version', 'invitationId', 'inviter', 'completion', 'eventIds', 'events'])
    if (d.version !== 1 || d.invitationId !== deriveInvitationId(invitation) || d.inviter !== invitation.inviter || d.completion !== 'eose') throw new Error('invalid invitation evidence binding or completion')
    const ids = dataArray(d.eventIds, MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS)
    const raw = dataArray(d.events, MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS)
    if (ids.length !== raw.length) throw new Error('invalid invitation evidence identities')
    const retained = new Map<string, string>(), retired: string[] = []
    let bytes = 0
    for (let i = 0; i < raw.length; i++) {
      const text = raw[i]
      if (typeof text !== 'string' || text.length > MAX_PERSISTENT_INVITATION_EVENT_BYTES) throw new Error('invalid evidence carrier')
      const carrierBytes = utf8.encode(text).length
      if (carrierBytes > MAX_PERSISTENT_INVITATION_EVENT_BYTES) throw new Error('oversized evidence carrier')
      bytes += carrierBytes
      if (bytes > MAX_PERSISTENT_INVITATION_EVIDENCE_BYTES) throw new Error('invitation evidence capacity exceeded')
      const c = carrier(JSON.parse(text))
      if (c.canonical !== text || c.event.id !== ids[i] || (i > 0 && (ids[i - 1] as string) >= c.event.id)) throw new Error('noncanonical invitation evidence')
      const admission = decodeEvidenceEvent(c.event, invitation)
      if (!admission) throw new Error('invalid signed invitation evidence')
      retained.set(c.event.id, text)
      if (admission === 'retired') retired.push(c.event.id)
      else decoded.push({ event: c.event, admission })
    }
    const evidence = observation(invitation, retained, 'eose')
    const held = (reason: Extract<PersistentInvitationEvidenceOutcome, { status: 'held' }>['reason']): PersistentInvitationEvidenceResult =>
      Object.freeze({ evidence, outcome: Object.freeze({ status: 'held', reason, retirementEventIds: Object.freeze(retired) }) })
    if (retired.length) return held('retired')
    if (!decoded.length) return held('unavailable')
    const first = decoded[0]!.admission.secret
    if (decoded.some(d => !d.admission.secret.every((b, i) => b === first[i]))) return held('conflicting-rooms')
    if (opts.expectedRoomSecret !== undefined && !first.every((b, i) => b === opts.expectedRoomSecret![i])) return held('wrong-room')
    const ends = decoded.filter(d => d.admission.endsAt !== undefined)
    const endsAt = ends.length ? Math.min(...ends.map(d => d.admission.endsAt!)) : undefined
    const destruct = decoded.filter(d => d.admission.destruct)
    const relayEvents = decoded.filter(d => d.admission.relays !== undefined)
    const newest = relayEvents.length ? Math.max(...relayEvents.map(d => d.event.created_at)) : undefined
    const winners = relayEvents.filter(d => d.event.created_at === newest)
    if (new Set(winners.map(d => JSON.stringify(d.admission.relays))).size > 1) return held('conflicting-relays')
    const relays = winners[0]?.admission.relays
    const storageEvents = decoded.filter(d => d.admission.storage !== undefined)
    const newestStorage = storageEvents.length ? Math.max(...storageEvents.map(d => d.event.created_at)) : undefined
    const storageWinners = storageEvents.filter(d => d.event.created_at === newestStorage)
    if (new Set(storageWinners.map(d => JSON.stringify(d.admission.storage))).size > 1) return held('conflicting-storage')
    const storage = storageWinners[0]?.admission.storage
    const admission: PersistentRoomAdmission = { secret: first.slice(), persistent: true, epoch: 0,
      ...(endsAt === undefined ? {} : { endsAt }), ...(destruct.length ? { destruct: true as const } : {}),
      ...(relays === undefined ? {} : { relays: [...relays] }),
      ...(storage === undefined ? {} : { storage: [...storage], storageAt: newestStorage! }) }
    const contributors = Object.freeze({ room: Object.freeze(decoded.map(d => d.event.id)),
      ends: Object.freeze(ends.filter(d => d.admission.endsAt === endsAt).map(d => d.event.id)),
      destruct: Object.freeze(destruct.map(d => d.event.id)), relays: Object.freeze(winners.map(d => d.event.id)),
      ...(storageWinners.length ? { storage: Object.freeze(storageWinners.map(d => d.event.id)) } : {}) })
    return Object.freeze({ evidence, outcome: Object.freeze({ status: 'admitted', admission, contributors }) })
  } finally {
    for (const d of decoded) d.admission.secret.fill(0)
    invitation.bearer.fill(0)
  }
}

/** Additive evidence query. No publication, storage, relay defaults or
 * membership authority. Only a complete bounded query can yield a result. */
export async function requestPersistentRoomAdmissionEvidence(opts: {
  transport: RelayTransport
  invitation: RoomInvitation
  timeoutMs?: number
  signal?: AbortSignal
}): Promise<PersistentInvitationEvidenceResult> {
  const invitation = copyInvitation(opts.invitation)
  const timeout = opts.timeoutMs ?? 15_000
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 2_147_483_647) { invitation.bearer.fill(0); throw new Error('invalid invitation evidence timeout') }
  try {
    return await new Promise((resolve, reject) => {
      const events = new Map<string, string>()
      let bytes = 0, received = 0, settled = false, unsub = () => {}
      const finish = (error?: unknown): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        opts.signal?.removeEventListener('abort', abort)
        try { unsub() } catch { /* Observer cleanup cannot revive a query. */ }
        if (error) reject(new PersistentInvitationEvidenceQueryError(error instanceof Error ? error.message : String(error), observation(invitation, events, 'incomplete')))
        else {
          try { resolve(revalidatePersistentInvitationEvidence({ evidence: observation(invitation, events, 'eose'), invitation })) }
          catch (error) { reject(error) }
        }
      }
      const abort = () => finish(new Error('invitation evidence query cancelled'))
      const timer = setTimeout(() => finish(new Error('invitation evidence query did not complete')), timeout)
      opts.signal?.addEventListener('abort', abort, { once: true })
      if (opts.signal?.aborted) { abort(); return }
      try {
        const invitationId = deriveInvitationId(invitation)
        // Canonical forms that were checked and refused, so a repeat of one costs no crypto.
        const refused = new Set<string>()
        let verifications = 0
        unsub = opts.transport.subscribe([{ kinds: [KINDS.GROUP_INVITATION, KINDS.INVITATION_RETIREMENT], authors: [invitation.inviter], '#d': [invitationId] }], event => {
          if (settled) return
          try {
            // Every delivery is charged first and bounds parse work. Retained
            // events, retained bytes and signature checks have their own limits.
            if (received >= MAX_PERSISTENT_INVITATION_EVIDENCE_DELIVERIES) throw new Error('invitation evidence query capacity exceeded: too many deliveries')
            received++
            let c: ReturnType<typeof carrier>
            try { c = carrier(event) } catch { return } // malformed or oversized: not evidence, not a failure
            if (!inAuthorityScope(c.event, invitation.inviter, invitationId)) return
            // An id already held was verified, so any other carrier with that id
            // has the same signed fields and nothing new to say. A carrier that
            // only claims it cannot verify. Dropping it loses no signed event.
            if (events.has(c.event.id) || refused.has(c.canonical)) return
            if (verifications >= MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS) throw new Error('invitation evidence query capacity exceeded: too many signature checks')
            verifications++
            const decoded = decodeEvidenceEvent(c.event, invitation)
            if (!decoded) { refused.add(c.canonical); return }
            if (decoded !== 'retired') decoded.secret.fill(0)
            // A valid authority event that no longer fits fails the query: never evict or truncate.
            if (events.size >= MAX_PERSISTENT_INVITATION_EVIDENCE_EVENTS || bytes + c.bytes > MAX_PERSISTENT_INVITATION_EVIDENCE_BYTES) throw new Error('invitation evidence query capacity exceeded')
            bytes += c.bytes
            events.set(c.event.id, c.canonical)
          } catch (error) { finish(error) }
        }, () => finish())
        // A synchronous transport can finish before returning its handle.
        if (settled) { try { unsub() } catch { /* Already terminal. */ } }
      } catch (error) { finish(error) }
    })
  } finally { invitation.bearer.fill(0) }
}
