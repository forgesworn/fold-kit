import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, type Event, type UnsignedEvent } from 'nostr-tools/pure'
import { randomBytes } from '@noble/hashes/utils'
import { verifyEventUncached } from './verify.js'
import { deriveRoom } from './room.js'
import { sanitiseDisplayName } from './display-name.js'
import { verifyDeviceCredential } from './credential.js'
import { MAX_ROOM_ENDS_SECONDS, withExpiration } from './expiration.js'
import { MAX_EPOCH } from './epoch.js'

const PROFILE = 'kithmoot/v1/node-room'
const EXISTING_PROFILE = 'kithmoot/v1/node-room-existing'
const ASK = 'kithmoot/v1/node-ask'
const ANSWER = 'kithmoot/v1/node-answer'
const RETIREMENT = 'kithmoot/v1/node-retirement'
export const NODE_ROOM_LABELS: readonly string[] = Object.freeze([PROFILE, ASK, ANSWER, RETIREMENT, EXISTING_PROFILE])
export const NODE_LINK_VERSION = 6
export const NODE_RECORD_KIND = 27542
export const NODE_CLOSE_KIND = 27543
export const NODE_RECEIPT_KIND = 27544
export const NODE_RETIREMENT_KIND = 1461
export const NODE_ASK_SECONDS = 600
const KEY = /^[0-9a-f]{64}$/
const utf8 = new TextEncoder(), text = new TextDecoder('utf-8', { fatal: true })

export interface NodeTurnPorts { udpTcp: number; tls: number }
export interface NodeRoomRecord {
  event: Event
  room: string
  authority: string
  origin: string
  serviceKey: string
  endsAt?: number
  turnPorts?: NodeTurnPorts
  relay: string
  iceUrls: string[]
  turnUrls: string[]
  /** An existing room keeps its original file and self-destruct choices.
   * This distinct signed profile is refused by older node-room readers. */
  existing?: { destruct: boolean }
}
export interface NodeJoinRequest {
  id: string
  device: string
  participant: string
  credential: Event
  name?: string
  expiresAt: number
}
export interface NodeRoomAdmission {
  secret: Uint8Array
  persistent: true
  epoch: 0
  epochHint: number
  destruct: boolean
  relays: string[]
  storage: []
  endsAt?: number
  grant: Event
  node: NodeRoomRecord
}
export interface CompactNodeClosure { id: string; sig: string; createdAt: number; operation: string; expiration: string }
export interface NodeCloseReceipt { operation: string; published: boolean; callsRevoked: true; relayPurged: true; eventsDeleted: number; completedAt: number }
function check(value: unknown): asserts value { if (!value) throw Error('invalid node room evidence') }
function integer(n: unknown): n is number { return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 }
function shape(value: unknown, required: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  check(value && typeof value === 'object' && !Array.isArray(value))
  const keys = Object.keys(value)
  check(required.every(k => keys.includes(k)) && keys.every(k => required.includes(k) || optional.includes(k)))
}
function json(raw: string, required: string[], optional: string[] = []): Record<string, unknown> {
  const value: unknown = JSON.parse(raw); shape(value, required, optional)
  check(JSON.stringify(value) === raw) // reject duplicate fields and ambiguous spelling
  return value
}
function event(raw: unknown, limit = 65536): asserts raw is Event {
  shape(raw, ['id', 'pubkey', 'sig', 'kind', 'created_at', 'content', 'tags'])
  check(typeof raw.id === 'string' && KEY.test(raw.id) && typeof raw.pubkey === 'string' && KEY.test(raw.pubkey)
    && typeof raw.sig === 'string' && /^[0-9a-f]{128}$/.test(raw.sig) && integer(raw.kind) && integer(raw.created_at)
    && typeof raw.content === 'string' && raw.content.length <= limit && Array.isArray(raw.tags) && raw.tags.length <= 16)
  for (const tag of raw.tags) check(Array.isArray(tag) && tag.length >= 1 && tag.length <= 4 && tag.every(v => typeof v === 'string' && v.length <= 512))
  check(utf8.encode(JSON.stringify(raw)).length <= limit && verifyEventUncached(raw as unknown as Event))
}
function tag(event: { tags: string[][] }, name: string): string {
  const matches = event.tags.filter(t => t[0] === name)
  check(matches.length === 1 && matches[0]!.length === 2)
  return matches[0]![1]!
}
function origin(raw: unknown): URL {
  check(typeof raw === 'string' && raw.length <= 253)
  const url = new URL(raw)
  check(url.protocol === 'https:' && url.origin === raw && !url.port && url.hostname.includes('.')
    && !/^[0-9.]+$/.test(url.hostname) && !url.hostname.includes(':')
    && !/\.(?:localhost|local|internal|home|invalid)$/.test(url.hostname)
    && url.hostname.split('.').every(s => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s)))
  return url
}
/** Only ports on the already pinned node hostname vary. HTTPS and the
 * dedicated TURN TLS hostname always retain port 443. */
export function readNodeTurnPorts(raw: unknown = undefined): NodeTurnPorts | null {
  if (raw === undefined) return { udpTcp: 3478, tls: 5349 }
  try {
    shape(raw, ['udpTcp', 'tls'])
    const ports = raw as unknown as NodeTurnPorts
    check([ports.udpTcp, ports.tls].every(value => Number.isSafeInteger(value) && value >= 1024 && value <= 65535) && ports.udpTcp !== ports.tls)
    return { udpTcp: ports.udpTcp, tls: ports.tls }
  } catch { return null }
}
const standardPorts = (ports: NodeTurnPorts): boolean => ports.udpTcp === 3478 && ports.tls === 5349
/** A signed record pins one node, its transport key and the privacy policy.
 * It contains no room traffic key, grant token, account key or device list. */
export function signNodeRoom(opts: { authoritySk: Uint8Array; room: string; origin: string; serviceKey: string; now: number; endsAt?: number; turnPorts?: NodeTurnPorts; existing?: { destruct: boolean } }): Event {
  const ports = readNodeTurnPorts(opts.turnPorts); check(ports)
  check(integer(opts.now) && KEY.test(opts.room) && KEY.test(opts.serviceKey) && opts.serviceKey !== getPublicKey(opts.authoritySk)); origin(opts.origin)
  if (opts.endsAt !== undefined) check(integer(opts.endsAt) && opts.endsAt > opts.now && opts.endsAt <= opts.now + MAX_ROOM_ENDS_SECONDS)
  if (opts.existing !== undefined) { shape(opts.existing, ['destruct']); check(typeof opts.existing.destruct === 'boolean') }
  return finalizeEvent({ kind: NODE_RECORD_KIND, created_at: opts.now,
    tags: withExpiration([['d', opts.room]], opts.endsAt), content: JSON.stringify({ v: 1, profile: opts.existing ? EXISTING_PROFILE : PROFILE, room: opts.room,
      node: opts.origin, service: opts.serviceKey, calls: 'relay-only', files: opts.existing ? 'client' : 'off',
      ...(opts.existing ? { destruct: opts.existing.destruct } : {}), ...(opts.endsAt === undefined ? {} : { ends: opts.endsAt }), ...(standardPorts(ports) ? {} : { turnPorts: ports }) }) }, opts.authoritySk)
}
export function readNodeRoom(raw: unknown, now: number, pinnedAuthority?: string): NodeRoomRecord | null {
  try {
    check(integer(now)); event(raw, 4096)
    check(raw.kind === NODE_RECORD_KIND && raw.created_at <= now + 30 && (pinnedAuthority === undefined || raw.pubkey === pinnedAuthority))
    const body = json(raw.content, ['v', 'profile', 'room', 'node', 'service', 'calls', 'files'], ['ends', 'turnPorts', 'destruct'])
    const existing = body.profile === EXISTING_PROFILE
    check(existing ? body.files === 'client' && typeof body.destruct === 'boolean' : body.profile === PROFILE && body.files === 'off' && !('destruct' in body))
    check(body.v === 1 && body.calls === 'relay-only'
      && typeof body.room === 'string' && KEY.test(body.room) && tag(raw, 'd') === body.room
      && typeof body.service === 'string' && KEY.test(body.service) && body.service !== raw.pubkey)
    const node = origin(body.node), ports = readNodeTurnPorts(body.turnPorts); check(ports)
    if (body.ends !== undefined) check(integer(body.ends) && body.ends > now && body.ends <= raw.created_at + MAX_ROOM_ENDS_SECONDS
      && tag(raw, 'expiration') === String(body.ends) && raw.tags.length === 2)
    else check(raw.tags.length === 1)
    return { event: JSON.parse(JSON.stringify(raw)), room: body.room, authority: raw.pubkey, origin: node.origin, serviceKey: body.service,
      ...(existing ? { existing: { destruct: body.destruct as boolean } } : {}),
      ...(body.ends === undefined ? {} : { endsAt: body.ends as number }), ...(standardPorts(ports) ? {} : { turnPorts: ports }), relay: `wss://${node.host}/events`,
      iceUrls: [`stun:${node.host}:${ports.udpTcp}`], turnUrls: [`turn:${node.host}:${ports.udpTcp}?transport=udp`, `turn:${node.host}:${ports.udpTcp}?transport=tcp`,
        `turns:${node.host}:${ports.tls}?transport=tcp`, `turns:turn.${node.host}:443?transport=tcp`] }
  } catch { return null }
}
function record(value: NodeRoomRecord, now: number): NodeRoomRecord {
  const verified = readNodeRoom(value.event, now, value.authority)
  check(verified); return verified
}
/** Version 6 deliberately stays outside parseRoomLink: an older client must
 * refuse this link instead of falling back to a bearer invitation. */
export function encodeNodeRoomLink(base: string, node: Event, now: number): string {
  check(readNodeRoom(node, now)); const url = new URL(base); check(url.protocol === 'https:' && !url.hash)
  return `${url.href}#${base64urlnopad.encode(utf8.encode(JSON.stringify({ v: NODE_LINK_VERSION, node })))}`
}
export function parseNodeRoomLink(link: string, now: number): NodeRoomRecord | null {
  try {
    const fragment = new URL(link).hash.slice(1); check(fragment.length > 0 && fragment.length <= 8192)
    const body = json(text.decode(base64urlnopad.decode(fragment)), ['v', 'node']); check(body.v === NODE_LINK_VERSION)
    return readNodeRoom(body.node, now)
  } catch { return null }
}
/** Apply the node's rolling NIP-40 horizon before signing, including for a
 * room with no fixed end. It never lengthens an existing shorter lifetime. */
export function withNodeRoomExpiration(tags: string[][], now: number, endsAt?: number): string[][] {
  check(integer(now) && now > 0 && (endsAt === undefined || integer(endsAt) && endsAt > now))
  return withExpiration(tags, Math.min(now + MAX_ROOM_ENDS_SECONDS, endsAt ?? Infinity))
}
/** A grant reset alone does not authorise deletion. This explicit statement
 * survives server room erasure without retaining room IDs or public keys. */
export function signNodeClosure(opts: { node: NodeRoomRecord; authoritySk: Uint8Array; operation: string; now: number }): Event {
  const node = record(opts.node, opts.now)
  check(getPublicKey(opts.authoritySk) === node.authority && /^[0-9a-f]{32}$/.test(opts.operation))
  return finalizeEvent({ kind: NODE_CLOSE_KIND, created_at: opts.now, content: '', tags: [['t', 'closed'], ['d', node.room],
    ['server', new URL(node.origin).hostname], ['operation', opts.operation], ['expiration', String(opts.now + MAX_ROOM_ENDS_SECONDS)]] }, opts.authoritySk)
}
export function readNodeClosure(raw: unknown, node: NodeRoomRecord, now: number): CompactNodeClosure | null {
  try {
    // A member may recover the proof after the room's fixed end; use the
    // descriptor's signed creation time to validate its immutable identity.
    const pinned = record(node, Math.min(now, node.endsAt === undefined ? now : node.endsAt - 1))
    event(raw, 4096)
    check(raw.kind === NODE_CLOSE_KIND && raw.pubkey === pinned.authority && raw.content === '' && raw.created_at <= now + 30
      && raw.tags.length === 5 && raw.tags.every(t => t.length === 2) && tag(raw, 't') === 'closed' && tag(raw, 'd') === pinned.room
      && tag(raw, 'server') === new URL(pinned.origin).hostname && /^[0-9a-f]{32}$/.test(tag(raw, 'operation'))
      && tag(raw, 'expiration') === String(raw.created_at + MAX_ROOM_ENDS_SECONDS) && raw.created_at + MAX_ROOM_ENDS_SECONDS > now)
    const canonical = [['t', 'closed'], ['d', pinned.room], ['server', new URL(pinned.origin).hostname], ['operation', tag(raw, 'operation')], ['expiration', tag(raw, 'expiration')]]
    check(JSON.stringify(raw.tags) === JSON.stringify(canonical))
    return { id: raw.id, sig: raw.sig, createdAt: raw.created_at, operation: tag(raw, 'operation'), expiration: tag(raw, 'expiration') }
  } catch { return null }
}
export function recoverNodeClosure(raw: unknown, node: NodeRoomRecord, now: number): Event | null {
  try {
    shape(raw, ['id', 'sig', 'createdAt', 'operation', 'expiration'])
    const proof = raw as unknown as CompactNodeClosure
    const event = { id: proof.id, sig: proof.sig, pubkey: node.authority, kind: NODE_CLOSE_KIND, created_at: proof.createdAt, content: '',
      tags: [['t', 'closed'], ['d', node.room], ['server', new URL(node.origin).hostname], ['operation', proof.operation], ['expiration', proof.expiration]] }
    return readNodeClosure(event, node, now) ? event : null
  } catch { return null }
}
/** Node links have no legacy invitation secret. Their retirement is signed
 * by the keeper and encrypted to the admitted room, bound to its descriptor
 * and durable close operation. The explicit closure statement remains the
 * independent deletion authority after the relay has been purged. */
export function signNodeRetirement(opts: { node: NodeRoomRecord; authoritySk: Uint8Array; roomSecret: Uint8Array; operation: string; now: number }): Event {
  const node = record(opts.node, opts.now), derived = deriveRoom(opts.roomSecret)
  try {
    check(derived.roomId === node.room && getPublicKey(opts.authoritySk) === node.authority && /^[0-9a-f]{32}$/.test(opts.operation))
    const content = nip44.v2.encrypt(JSON.stringify({ v: 1, profile: RETIREMENT, descriptor: node.event.id, operation: opts.operation, closed: true }), derived.roomKey)
    return finalizeEvent({ kind: NODE_RETIREMENT_KIND, created_at: opts.now,
      tags: withNodeRoomExpiration([['d', node.room]], opts.now, node.endsAt), content }, opts.authoritySk)
  } finally { derived.roomKey.fill(0) }
}
export function readNodeRetirement(raw: unknown, node: NodeRoomRecord, roomSecret: Uint8Array, now: number): { operation: string; at: number } | null {
  let key: Uint8Array | undefined
  try {
    const pinned = record(node, now), derived = deriveRoom(roomSecret); key = derived.roomKey
    event(raw, 4096)
    check(derived.roomId === pinned.room && raw.kind === NODE_RETIREMENT_KIND && raw.pubkey === pinned.authority && raw.created_at <= now + 30
      && raw.tags.length === 2 && tag(raw, 'd') === pinned.room && Number(tag(raw, 'expiration')) > now
      && tag(raw, 'expiration') === String(Math.min(raw.created_at + MAX_ROOM_ENDS_SECONDS, pinned.endsAt ?? Infinity)))
    const body = json(nip44.v2.decrypt(raw.content, key), ['v', 'profile', 'descriptor', 'operation', 'closed'])
    check(body.v === 1 && body.profile === RETIREMENT && body.descriptor === pinned.event.id && body.closed === true
      && typeof body.operation === 'string' && /^[0-9a-f]{32}$/.test(body.operation))
    return { operation: body.operation, at: raw.created_at }
  } catch { return null } finally { key?.fill(0) }
}
/** A receipt authenticates what the node reports. Device deletion still
 * requires the keeper's closure statement, never the node's signature alone. */
export function readNodeCloseReceipt(raw: unknown, node: NodeRoomRecord, operation: string, now: number): NodeCloseReceipt | null {
  try {
    const pinned = record(node, Math.min(now, node.endsAt === undefined ? now : node.endsAt - 1))
    return readNodeOperationReceipt(raw, pinned.serviceKey, operation, now)
  } catch { return null }
}
/** After self-destruct the owner keeps only the paired public service key
 * and random operation id. Verifying completion needs no room descriptor,
 * room id, member identity or traffic key. This never authorises a wipe. */
export function readNodeOperationReceipt(raw: unknown, serviceKey: string, operation: string, now: number): NodeCloseReceipt | null {
  try {
    event(raw, 8192)
    check(integer(now) && KEY.test(serviceKey) && /^[0-9a-f]{32}$/.test(operation) && raw.kind === NODE_RECEIPT_KIND && raw.pubkey === serviceKey
      && raw.created_at <= now + 30 && raw.tags.length === 2 && tag(raw, 'operation') === operation
      && tag(raw, 'expiration') === String(raw.created_at + MAX_ROOM_ENDS_SECONDS) && raw.created_at + MAX_ROOM_ENDS_SECONDS > now)
    const body = json(raw.content, ['v', 'operation', 'published', 'callsRevoked', 'relayPurged', 'eventsDeleted', 'completedAt'])
    check(body.v === 1 && body.operation === operation && typeof body.published === 'boolean' && body.callsRevoked === true && body.relayPurged === true
      && integer(body.eventsDeleted) && body.completedAt === raw.created_at)
    return { operation, published: body.published, callsRevoked: true, relayPurged: true, eventsDeleted: body.eventsDeleted, completedAt: raw.created_at }
  } catch { return null }
}
function gift(kind: number, content: Record<string, unknown>, sender: Uint8Array, recipient: string, now: number, expiration: number): { event: Event; id: string } {
  const rumor: UnsignedEvent & { id?: string } = { kind, created_at: now, tags: [], content: JSON.stringify(content), pubkey: getPublicKey(sender) }
  rumor.id = getEventHash(rumor)
  const seal = finalizeEvent({ kind: 13, created_at: now, tags: [], content: nip44.v2.encrypt(JSON.stringify(rumor), nip44.v2.utils.getConversationKey(sender, recipient)) }, sender)
  const outer = generateSecretKey()
  try {
    return { id: rumor.id, event: finalizeEvent({ kind: 1059, created_at: now, tags: [['p', recipient], ['expiration', String(expiration)]],
      content: nip44.v2.encrypt(JSON.stringify(seal), nip44.v2.utils.getConversationKey(outer, recipient)) }, outer) }
  } finally { outer.fill(0) }
}
function unwrap(raw: unknown, recipient: Uint8Array, now: number): { rumor: UnsignedEvent & { id: string }; expiration: number } {
  event(raw); check(raw.kind === 1059 && raw.tags.length === 2 && tag(raw, 'p') === getPublicKey(recipient)
    && raw.created_at <= now + 30 && raw.created_at >= now - NODE_ASK_SECONDS)
  const expiration = Number(tag(raw, 'expiration'))
  check(integer(expiration) && String(expiration) === tag(raw, 'expiration') && expiration > now && expiration <= raw.created_at + NODE_ASK_SECONDS)
  const seal: unknown = JSON.parse(nip44.v2.decrypt(raw.content, nip44.v2.utils.getConversationKey(recipient, raw.pubkey)))
  event(seal, 49152); check(seal.kind === 13 && seal.tags.length === 0 && seal.created_at === raw.created_at)
  const rumor: unknown = JSON.parse(nip44.v2.decrypt(seal.content, nip44.v2.utils.getConversationKey(recipient, seal.pubkey)))
  shape(rumor, ['id', 'kind', 'created_at', 'tags', 'content', 'pubkey'])
  check(rumor.pubkey === seal.pubkey && integer(rumor.created_at) && rumor.created_at === raw.created_at && Array.isArray(rumor.tags)
    && rumor.tags.length === 0 && typeof rumor.content === 'string' && typeof rumor.kind === 'number'
    && getEventHash(rumor as unknown as UnsignedEvent) === rumor.id)
  return { rumor: rumor as unknown as UnsignedEvent & { id: string }, expiration }
}
export function encodeNodeJoinRequest(opts: { node: NodeRoomRecord; deviceSk: Uint8Array; credential: Event; now: number; name?: string }): { event: Event; requestId: string; expiresAt: number } {
  const node = record(opts.node, opts.now), device = getPublicKey(opts.deviceSk)
  event(opts.credential, 8192)
  const verified = verifyDeviceCredential(opts.credential, { roomId: node.room, now: opts.now })
  check(verified.ok && verified.device === device && device !== node.authority && device !== node.serviceKey)
  const name = sanitiseDisplayName(opts.name), expiresAt = Math.min(opts.now + NODE_ASK_SECONDS, node.endsAt ?? Infinity)
  const result = gift(20466, { v: 1, profile: ASK, descriptor: node.event.id, nonce: base64urlnopad.encode(randomBytes(32)),
    room: node.room, credential: opts.credential, ...(name === undefined ? {} : { name }) }, opts.deviceSk, node.authority, opts.now, expiresAt)
  return { event: result.event, requestId: result.id, expiresAt }
}
export function decodeNodeJoinRequest(opts: { node: NodeRoomRecord; authoritySk: Uint8Array; event: unknown; now: number }): NodeJoinRequest | null {
  try {
    const node = record(opts.node, opts.now); check(getPublicKey(opts.authoritySk) === node.authority)
    const { rumor, expiration } = unwrap(opts.event, opts.authoritySk, opts.now)
    check(rumor.kind === 20466)
    const body = json(rumor.content, ['v', 'profile', 'descriptor', 'nonce', 'room', 'credential'], ['name'])
    check(body.v === 1 && body.profile === ASK && body.descriptor === node.event.id && body.room === node.room
      && typeof body.nonce === 'string' && /^[A-Za-z0-9_-]{43}$/.test(body.nonce))
    event(body.credential, 8192)
    const verified = verifyDeviceCredential(body.credential, { roomId: node.room, now: opts.now })
    check(verified.ok && verified.device === rumor.pubkey && rumor.pubkey !== node.authority && rumor.pubkey !== node.serviceKey)
    const name = sanitiseDisplayName(typeof body.name === 'string' ? body.name : undefined)
    check(body.name === undefined || body.name === name)
    return { id: rumor.id, device: verified.device, participant: verified.participant, credential: body.credential, expiresAt: expiration, ...(name === undefined ? {} : { name }) }
  } catch { return null }
}
/** Node v1's strict active-grant subset. Full grant-ledger ordering and
 * terminal revocation remain the supervisor/client grant receiver's job. */
export function verifyNodeRoomGrant(raw: unknown, node: NodeRoomRecord, device: string, now: number): raw is Event {
  try {
    const pinned = record(node, now); event(raw, 16384)
    check(raw.kind === 27541 && raw.pubkey === pinned.authority && raw.content === '' && raw.created_at <= now + 30)
    check(raw.tags.length === 10 && raw.tags.every(t => t.length === 2))
    check(tag(raw, 't') === 'grant' && /^[0-9a-f]{32}$/.test(tag(raw, 'grant')) && tag(raw, 'd') === pinned.room
      && tag(raw, 'device') === device && device !== pinned.authority && device !== pinned.serviceKey && tag(raw, 'server') === new URL(pinned.origin).hostname
      && tag(raw, 'status') === 'active')
    const scopes = raw.tags.filter(t => t[0] === 'scope').map(t => t[1]).sort()
    check(JSON.stringify(scopes) === JSON.stringify(['relay-read', 'relay-write', 'turn']))
    const expiration = Number(tag(raw, 'expiration'))
    check(integer(expiration) && String(expiration) === tag(raw, 'expiration') && expiration > now && expiration <= raw.created_at + 90 * 86400)
    check(raw.tags.every(t => ['t', 'grant', 'd', 'device', 'server', 'status', 'expiration', 'scope'].includes(t[0]!)))
    return true
  } catch { return false }
}
export function encodeNodeJoinAnswer(opts: { node: NodeRoomRecord; authoritySk: Uint8Array; request: unknown; now: number;
  admission?: { roomSecret: Uint8Array; epochHint: number; grant: Event } }): Event {
  const node = record(opts.node, opts.now), request = decodeNodeJoinRequest({ node, authoritySk: opts.authoritySk, event: opts.request, now: opts.now })
  check(request)
  if (opts.admission) check(deriveRoom(opts.admission.roomSecret).roomId === node.room && integer(opts.admission.epochHint) && opts.admission.epochHint <= MAX_EPOCH
    && verifyNodeRoomGrant(opts.admission.grant, node, request.device, opts.now))
  const expiresAt = Math.min(request.expiresAt, opts.now + 90, node.endsAt ?? Infinity)
  return gift(20467, { v: 1, profile: ANSWER, descriptor: node.event.id, room: node.room, request: request.id, device: request.device,
    outcome: opts.admission ? 'allow' : 'deny', ...(opts.admission ? { secret: base64urlnopad.encode(opts.admission.roomSecret), epoch: opts.admission.epochHint, grant: opts.admission.grant } : {}) },
    opts.authoritySk, request.device, opts.now, expiresAt).event
}
export function decodeNodeJoinAnswer(opts: { node: NodeRoomRecord; deviceSk: Uint8Array; event: unknown; requestId: string; requestExpiresAt: number; now: number }): NodeRoomAdmission | 'denied' | null {
  try {
    const node = record(opts.node, opts.now), device = getPublicKey(opts.deviceSk)
    check(KEY.test(opts.requestId) && integer(opts.requestExpiresAt) && opts.requestExpiresAt > opts.now)
    const { rumor, expiration } = unwrap(opts.event, opts.deviceSk, opts.now)
    check(rumor.kind === 20467 && rumor.pubkey === node.authority && expiration <= opts.requestExpiresAt && expiration <= rumor.created_at + 90)
    const body = json(rumor.content, ['v', 'profile', 'descriptor', 'room', 'request', 'device', 'outcome'], ['secret', 'epoch', 'grant'])
    check(body.v === 1 && body.profile === ANSWER && body.descriptor === node.event.id && body.room === node.room && body.request === opts.requestId && body.device === device)
    if (body.outcome === 'deny') { check(Object.keys(body).length === 7); return 'denied' }
    check(body.outcome === 'allow' && typeof body.secret === 'string' && integer(body.epoch) && body.epoch <= MAX_EPOCH && verifyNodeRoomGrant(body.grant, node, device, opts.now))
    const secret = base64urlnopad.decode(body.secret)
    try { check(secret.length === 32 && deriveRoom(secret).roomId === node.room) } catch (error) { secret.fill(0); throw error }
    return { secret, persistent: true, epoch: 0, epochHint: body.epoch, destruct: node.existing?.destruct ?? true, relays: [node.relay], storage: [], grant: body.grant as Event,
      node, ...(node.endsAt === undefined ? {} : { endsAt: node.endsAt }) }
  } catch { return null }
}
