import { base64urlnopad } from '@scure/base'
import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
import { verifyEventUncached } from './verify.js'
import { readNodeRoom, verifyNodeRoomGrant, type NodeRoomRecord } from './node-room.js'

const PROFILE = 'kithmoot/v1/node-migration'
const READY = 'kithmoot/v1/node-migration-ready'
export const NODE_MIGRATION_LABELS: readonly string[] = Object.freeze([PROFILE, READY])
export const NODE_MIGRATION_KIND = 27545
export const NODE_MIGRATION_READY_KIND = 27546
export const NODE_MIGRATION_SECONDS = 600
export const MAX_NODE_MIGRATION_ENDPOINTS = 16
const KEY = /^[a-f0-9]{64}$/
const OPERATION = /^[a-f0-9]{32}$/
const SID = /^[A-Za-z0-9_-]{8,128}$/
const utf8 = new TextEncoder()
export interface NodeMigrationEndpoint { device: string; sid: string }
export interface NodeMigrationHistory { events: number; digest: string }
export interface NodeMigrationPreparation {
  event: Event; node: NodeRoomRecord; operation: string; endpoints: NodeMigrationEndpoint[]; epoch: number; expiresAt: number
}
export interface NodeMigrationReady {
  event: Event; endpoint: NodeMigrationEndpoint; grant: Event; history: NodeMigrationHistory
}
export interface NodeMigrationCommit { event: Event; preparation: NodeMigrationPreparation; ready: NodeMigrationReady[] }
function check(value: unknown): asserts value { if (!value) throw Error('Invalid node migration evidence') }
const integer = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0
export const nodeMigrationEndpointId = (endpoint: NodeMigrationEndpoint): string => `${endpoint.device}:${endpoint.sid}`
function endpoints(raw: unknown): NodeMigrationEndpoint[] {
  check(Array.isArray(raw) && raw.length > 0 && raw.length <= MAX_NODE_MIGRATION_ENDPOINTS)
  const list = raw.map(value => {
    check(value && typeof value === 'object' && Object.keys(value).sort().join(',') === 'device,sid'
      && typeof value.device === 'string' && KEY.test(value.device) && typeof value.sid === 'string' && SID.test(value.sid))
    return { device: value.device as string, sid: value.sid as string }
  }).sort((a,b) => nodeMigrationEndpointId(a) < nodeMigrationEndpointId(b) ? -1 : nodeMigrationEndpointId(a) > nodeMigrationEndpointId(b) ? 1 : 0)
  check(new Set(list.map(nodeMigrationEndpointId)).size === list.length)
  return list
}
function readEvent(raw: unknown, kind: number, now: number, authority?: string): { event: Event; body: Record<string, unknown>; expiresAt: number } {
  check(integer(now) && raw && typeof raw === 'object' && !Array.isArray(raw))
  const value = raw as Event
  check(Object.keys(value).sort().join(',') === 'content,created_at,id,kind,pubkey,sig,tags'
    && value.kind === kind && integer(value.created_at) && value.created_at <= now + 30
    && typeof value.id === 'string' && KEY.test(value.id) && typeof value.pubkey === 'string' && KEY.test(value.pubkey)
    && typeof value.sig === 'string' && /^[a-f0-9]{128}$/.test(value.sig)
    && typeof value.content === 'string' && utf8.encode(JSON.stringify(value)).length <= 131072
    && (authority === undefined || value.pubkey === authority) && Array.isArray(value.tags) && value.tags.length === 2)
  check(value.tags.every(t => Array.isArray(t) && t.length === 2 && t.every(s => typeof s === 'string' && s.length <= 128)))
  const expiry = value.tags.filter(t => t[0] === 'expiration'), room = value.tags.filter(t => t[0] === 'd')
  check(expiry.length === 1 && room.length === 1 && KEY.test(room[0]![1]!))
  const expiresAt = Number(expiry[0]![1])
  check(integer(expiresAt) && String(expiresAt) === expiry[0]![1] && expiresAt > now && expiresAt > value.created_at && verifyEventUncached(value))
  const body: unknown = JSON.parse(value.content)
  check(body && typeof body === 'object' && !Array.isArray(body) && JSON.stringify(body) === value.content)
  return { event: JSON.parse(JSON.stringify(value)), body: body as Record<string,unknown>, expiresAt }
}
function shape(body: Record<string, unknown>, names: string[]): void { check(Object.keys(body).sort().join(',') === [...names].sort().join(',')) }
function roomTag(event: Event): string { return event.tags.find(t => t[0] === 'd')![1]! }
function history(raw: unknown): NodeMigrationHistory {
  check(raw && typeof raw === 'object' && !Array.isArray(raw))
  const value = raw as NodeMigrationHistory
  check(Object.keys(value).sort().join(',') === 'digest,events' && integer(value.events) && value.events <= 1_000_000 && typeof value.digest === 'string' && KEY.test(value.digest))
  return { events: value.events, digest: value.digest }
}
/** Hash original signed IDs, never reconstructed/decrypted messages. */
export function nodeMigrationDigest(ids: readonly string[]): string {
  check(ids.length <= 1_000_000 && ids.every(id => KEY.test(id)))
  return bytesToHex(sha256(utf8.encode([...new Set(ids)].sort().join('\n'))))
}
export function readNodeMigrationPreparation(raw: unknown, now: number, authority: string): NodeMigrationPreparation | null {
  try {
    const { event, body, expiresAt } = readEvent(raw,NODE_MIGRATION_KIND,now,authority)
    shape(body,['v','profile','phase','operation','node','endpoints','epoch'])
    check(body.v === 1 && body.profile === PROFILE && body.phase === 'prepare' && typeof body.operation === 'string' && OPERATION.test(body.operation)
      && integer(body.epoch) && body.epoch <= 0x7fffffff)
    const node=readNodeRoom(body.node,now,authority); check(node?.existing && roomTag(event)===node.room)
    check(expiresAt===Math.min(event.created_at+NODE_MIGRATION_SECONDS,node.endsAt??Infinity) && event.created_at>=node.event.created_at)
    const required=endpoints(body.endpoints); check(JSON.stringify(required)===JSON.stringify(body.endpoints))
    return {event,node,operation:body.operation,endpoints:required,epoch:body.epoch,expiresAt}
  } catch { return null }
}
export function signNodeMigrationPreparation(opts: {node:NodeRoomRecord;authoritySk:Uint8Array;operation:string;endpoints:NodeMigrationEndpoint[];epoch:number;now:number}): Event {
  const event=finalizeEvent({kind:NODE_MIGRATION_KIND,created_at:opts.now,tags:[['d',opts.node.room],['expiration',String(Math.min(opts.now+NODE_MIGRATION_SECONDS,opts.node.endsAt??Infinity))]],
    content:JSON.stringify({v:1,profile:PROFILE,phase:'prepare',operation:opts.operation,node:opts.node.event,endpoints:endpoints(opts.endpoints),epoch:opts.epoch})},opts.authoritySk)
  check(readNodeMigrationPreparation(event,opts.now,opts.node.authority)); return event
}
export function readNodeMigrationReady(raw:unknown,preparation:NodeMigrationPreparation,now:number):NodeMigrationReady|null {
  try {
    const prepared=readNodeMigrationPreparation(preparation.event,now,preparation.node.authority);check(prepared)
    const {event,body,expiresAt}=readEvent(raw,NODE_MIGRATION_READY_KIND,now)
    shape(body,['v','profile','preparation','operation','node','sid','grant','history'])
    check(body.v===1&&body.profile===READY&&body.preparation===prepared.event.id&&body.operation===prepared.operation&&body.node===prepared.node.event.id
      &&roomTag(event)===prepared.node.room&&event.created_at>=prepared.event.created_at&&expiresAt===prepared.expiresAt&&typeof body.sid==='string')
    const endpoint={device:event.pubkey,sid:body.sid}
    check(prepared.endpoints.some(e=>nodeMigrationEndpointId(e)===nodeMigrationEndpointId(endpoint)))
    check(verifyNodeRoomGrant(body.grant,prepared.node,event.pubkey,now))
    return {event,endpoint,grant:JSON.parse(JSON.stringify(body.grant)) as Event,history:history(body.history)}
  } catch { return null }
}
export function signNodeMigrationReady(opts:{preparation:NodeMigrationPreparation;deviceSk:Uint8Array;sid:string;grant:Event;history:NodeMigrationHistory;now:number}):Event {
  const prepared=opts.preparation
  const event=finalizeEvent({kind:NODE_MIGRATION_READY_KIND,created_at:opts.now,tags:[['d',prepared.node.room],['expiration',String(prepared.expiresAt)]],
    content:JSON.stringify({v:1,profile:READY,preparation:prepared.event.id,operation:prepared.operation,node:prepared.node.event.id,sid:opts.sid,grant:opts.grant,history:history(opts.history)})},opts.deviceSk)
  check(event.pubkey===getPublicKey(opts.deviceSk)&&readNodeMigrationReady(event,prepared,opts.now));return event
}
export function readNodeMigrationCommit(raw:unknown,now:number,authority:string):NodeMigrationCommit|null {
  try {
    const {event,body,expiresAt}=readEvent(raw,NODE_MIGRATION_KIND,now,authority)
    shape(body,['v','profile','phase','preparation','ready'])
    check(body.v===1&&body.profile===PROFILE&&body.phase==='commit'&&Array.isArray(body.ready))
    const preparation=readNodeMigrationPreparation(body.preparation,event.created_at,authority);check(preparation)
    check(roomTag(event)===preparation.node.room&&event.created_at>=preparation.event.created_at
      &&expiresAt===Math.min(event.created_at+30*86400,preparation.node.endsAt??Infinity)&&body.ready.length===preparation.endpoints.length)
    const ready=body.ready.map(raw=>{const value=readNodeMigrationReady(raw,preparation,event.created_at);check(value&&value.event.created_at<=event.created_at);return value})
    const required=new Set(preparation.endpoints.map(nodeMigrationEndpointId)), seen=new Set<string>()
    for(const value of ready){const id=nodeMigrationEndpointId(value.endpoint);check(required.has(id)&&!seen.has(id));seen.add(id)}
    return {event,preparation,ready}
  } catch { return null }
}
export function signNodeMigrationCommit(opts:{preparation:NodeMigrationPreparation;authoritySk:Uint8Array;ready:Event[];now:number}):Event {
  const prepared=opts.preparation
  const event=finalizeEvent({kind:NODE_MIGRATION_KIND,created_at:opts.now,tags:[['d',prepared.node.room],['expiration',String(Math.min(opts.now+30*86400,prepared.node.endsAt??Infinity))]],
    content:JSON.stringify({v:1,profile:PROFILE,phase:'commit',preparation:prepared.event,ready:opts.ready})},opts.authoritySk)
  check(readNodeMigrationCommit(event,opts.now,prepared.node.authority));return event
}

/** A fragment is only a carrier INSIDE authenticated encrypted room control
 * messages. Its digest binds the complete original signed wire bytes. */
export interface NodeMigrationFrame { op: 'node-migration'; v: 1; id: string; part: number; total: number; data: string }
export const NODE_MIGRATION_FRAME_CHARS = 1024
const MAX_WIRE_BYTES = 131072
const MAX_FRAME_CHARS = Math.ceil(MAX_WIRE_BYTES * 4 / 3)
const MAX_FRAMES = Math.ceil(MAX_FRAME_CHARS / NODE_MIGRATION_FRAME_CHARS)
function signedWire(raw: unknown): Event | null {
  try {
    check(raw && typeof raw === 'object' && !Array.isArray(raw))
    const e = raw as Event
    check(Object.keys(e).sort().join(',') === 'content,created_at,id,kind,pubkey,sig,tags'
      && [NODE_MIGRATION_KIND, NODE_MIGRATION_READY_KIND, 27542].includes(e.kind) && verifyEventUncached(e))
    return e
  } catch { return null }
}
export function readNodeMigrationFrame(raw: unknown): NodeMigrationFrame | null {
  try {
    check(raw && typeof raw === 'object' && !Array.isArray(raw))
    const f = raw as NodeMigrationFrame
    check(Object.keys(f).sort().join(',') === 'data,id,op,part,total,v' && f.op === 'node-migration' && f.v === 1
      && typeof f.id === 'string' && KEY.test(f.id) && integer(f.total) && f.total > 0 && f.total <= MAX_FRAMES
      && integer(f.part) && f.part < f.total && typeof f.data === 'string' && /^[A-Za-z0-9_-]+$/.test(f.data)
      && f.data.length <= NODE_MIGRATION_FRAME_CHARS && (f.part === f.total - 1 || f.data.length === NODE_MIGRATION_FRAME_CHARS))
    return { op: 'node-migration', v: 1, id: f.id, part: f.part, total: f.total, data: f.data }
  } catch { return null }
}
export function encodeNodeMigrationFrames(raw: Event): NodeMigrationFrame[] {
  check(signedWire(raw))
  const wire = utf8.encode(JSON.stringify(raw)); check(wire.length <= MAX_WIRE_BYTES)
  const data = base64urlnopad.encode(wire), id = bytesToHex(sha256(wire)), total = Math.ceil(data.length / NODE_MIGRATION_FRAME_CHARS)
  return Array.from({ length: total }, (_, part) => ({ op: 'node-migration', v: 1, id, part, total,
    data: data.slice(part * NODE_MIGRATION_FRAME_CHARS, (part + 1) * NODE_MIGRATION_FRAME_CHARS) }))
}
/** One receiver per room. `source` comes from the outer control message's
 * verified sender, never a value claimed by the fragment. All bounds are
 * enforced before reserving memory; expired or conflicting assemblies vanish. */
export class NodeMigrationFrameReceiver {
  readonly #pending = new Map<string, { source: string; at: number; total: number; parts: Map<number, string> }>()
  readonly #completed = new Map<string, number>()
  push(raw: unknown, source: string, now: number): Event | null {
    if (!KEY.test(source) || !integer(now)) return null
    for (const [id, value] of this.#pending) if (now < value.at || value.at + 300 <= now) this.#pending.delete(id)
    for (const [id, at] of this.#completed) if (now < at || at + 300 <= now) this.#completed.delete(id)
    const frame = readNodeMigrationFrame(raw); if (!frame) return null
    const key = `${source}:${frame.id}`
    if (this.#completed.has(key)) return null
    let pending = this.#pending.get(key)
    if (!pending) {
      if (this.#pending.size >= 8 || [...this.#pending.values()].filter(v => v.source === source).length >= 2) return null
      pending = { source, at: now, total: frame.total, parts: new Map() }; this.#pending.set(key, pending)
    }
    if (pending.total !== frame.total || pending.parts.has(frame.part) && pending.parts.get(frame.part) !== frame.data) {
      this.#pending.delete(key); return null
    }
    pending.parts.set(frame.part, frame.data)
    if (pending.parts.size !== pending.total) return null
    this.#pending.delete(key)
    try {
      const data = Array.from({ length: pending.total }, (_, part) => pending.parts.get(part)!).join('')
      check(data.length <= MAX_FRAME_CHARS)
      const wire = base64urlnopad.decode(data)
      check(wire.length <= MAX_WIRE_BYTES && base64urlnopad.encode(wire) === data && bytesToHex(sha256(wire)) === frame.id)
      const event = signedWire(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(wire))); check(event)
      if (this.#completed.size >= 64) this.#completed.delete(this.#completed.keys().next().value!)
      this.#completed.set(key, now)
      return event
    } catch { return null }
  }
  clear(): void { this.#pending.clear(); this.#completed.clear() }
}
