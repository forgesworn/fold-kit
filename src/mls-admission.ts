import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { base64, base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure'
import { isSealPubkey } from './seal.js'
import { verifyEventUncached } from './verify.js'
import type { UnsignedEvent } from './identity.js'

const ID = 'kithmoot/v4/mls-invitation-id'
const REQUEST_KEY = 'kithmoot/v4/mls-request-key'
const ANSWER_KEY = 'kithmoot/v4/mls-answer-key'
const REQUEST = 'kithmoot/v4/mls-request'
const ANSWER = 'kithmoot/v4/mls-answer'
const ACCOUNT = 'kithmoot/v4/mls-joiner-account-proof'
const BROWSER = 'kithmoot/v4/mls-browser-device-proof'
const ENGINE = 'kithmoot/v4/mls-engine-device-proof'
const KEEPER_ACCOUNT = 'kithmoot/v4/mls-keeper-account-proof'
const KEEPER_DEVICE = 'kithmoot/v4/mls-keeper-device-proof'
export const MLS_ADMISSION_LABELS: readonly string[] = Object.freeze([
  ID, REQUEST_KEY, ANSWER_KEY, REQUEST, ANSWER, ACCOUNT, BROWSER, ENGINE,
  KEEPER_ACCOUNT, KEEPER_DEVICE,
])
export const MLS_ADMISSION_PLAINTEXT_BYTES = 16_384
export const MLS_ADMISSION_CIPHERTEXT_CHARACTERS = 21_936
const HEX = /^[0-9a-f]{64}$/
const SIG = /^[0-9a-f]{128}$/
const DECIMAL = /^(0|[1-9][0-9]*)$/
const utf8 = new TextEncoder()
const text = new TextDecoder('utf-8', { fatal: true })
const FAILURE = 'invalid MLS admission v4'

/** Evidence only. No admission/capability constructor is exported. */
export interface VerifiedMlsAdmissionRequest {
  readonly __verifiedMlsAdmissionRequest: unique symbol
}
export interface VerifiedAdmissionAnswer {
  readonly __verifiedAdmissionAnswer: unique symbol
}
interface Invitation { root: string; bearer: Uint8Array; id: string }
type PublicInvitation = Pick<Invitation, 'root' | 'id'>
interface RequestEvidence { root: string; invitationId: string; core: unknown[]; digest: string; event: Event }
interface AnswerEvidence { core: unknown[]; digest: string; event: Event; requestEventId: string }
const requests = new WeakMap<object, RequestEvidence>()
const answers = new WeakMap<object, AnswerEvidence>()

function check(ok: unknown): asserts ok {
  if (!ok) throw new Error(FAILURE)
}
function integer(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)
}
function hex(value: unknown): value is string { return typeof value === 'string' && HEX.test(value) }
function pubkey(value: unknown): value is string { return hex(value) && isSealPubkey(value) }
function time(value: unknown): asserts value is number { check(integer(value)) }
function digest(value: unknown): string { return bytesToHex(sha256(utf8.encode(JSON.stringify(value)))) }
function same(a: unknown, b: unknown): boolean { return JSON.stringify(a) === JSON.stringify(b) }
function array(value: unknown, length: number): asserts value is unknown[] {
  check(Array.isArray(value) && value.length === length)
}

// Every wire-facing decoder accepts bounded strings, never caller event objects
// or proxies with verification markers/accessors. Scan depth before JSON.parse.
function parse(raw: unknown, max: number, canonical = true): unknown {
  check(typeof raw === 'string' && raw.length <= max && utf8.encode(raw).length <= max)
  let depth = 0, quoted = false, escaped = false
  for (const c of raw) {
    if (quoted) {
      if (escaped) escaped = false
      else if (c === '\\') escaped = true
      else if (c === '"') quoted = false
    } else if (c === '"') quoted = true
    else if (c === '[' || c === '{') check(++depth <= 8)
    else if (c === ']' || c === '}') check(--depth >= 0)
  }
  check(depth === 0 && !quoted)
  let value: unknown
  try { value = JSON.parse(raw) } catch { throw new Error(FAILURE) }
  if (canonical) check(JSON.stringify(value) === raw)
  return value
}
function secret<T>(foreign: Uint8Array, action: (owned: Uint8Array) => T): T {
  check(foreign instanceof Uint8Array && foreign.length === 32)
  const owned = new Uint8Array(foreign)
  try { getPublicKey(owned); return action(owned) }
  finally { owned.fill(0) }
}
function invitation(fragment: string): Invitation {
  check(typeof fragment === 'string' && fragment.length <= 1024 && /^[A-Za-z0-9_-]+$/.test(fragment))
  const decoded = base64urlnopad.decode(fragment)
  let bearer: Uint8Array | undefined, transferred = false
  try {
    check(base64urlnopad.encode(decoded) === fragment)
    const value = parse(text.decode(decoded), 1024)
    array(value, 3)
    check(value[0] === 4 && typeof value[1] === 'string' && pubkey(value[2]))
    bearer = base64urlnopad.decode(value[1])
    check(bearer.length === 32 && bearer.some(b => b !== 0) && base64urlnopad.encode(bearer) === value[1])
    const root = value[2]
    const result = { root, bearer, id: bytesToHex(hkdf(sha256, bearer, hexToBytes(root), ID, 32)) }
    transferred = true
    return result
  } finally {
    decoded.fill(0)
    if (!transferred) bearer?.fill(0)
  }
}
/** Link fragment only; caller owns CSPRNG generation and secret lifetime. */
export function encodeMlsInvitationV4(root: string, bearer: Uint8Array): string {
  check(pubkey(root) && bearer instanceof Uint8Array && bearer.length === 32 && bearer.some(b => b !== 0))
  return base64urlnopad.encode(utf8.encode(JSON.stringify([4, base64urlnopad.encode(bearer), root])))
}
export function readMlsInvitationV4(fragment: string): { root: string; bearer: Uint8Array; invitationId: string } {
  const i = invitation(fragment)
  return { root: i.root, bearer: i.bearer, invitationId: i.id }
}
function withKey<T>(i: Invitation, sk: Uint8Array, peer: string, direction: string, action: (key: Uint8Array) => T): T {
  const base = nip44.v2.utils.getConversationKey(sk, peer)
  let key: Uint8Array | undefined
  try { key = hkdf(sha256, base, i.bearer, direction, 32); return action(key) }
  finally { base.fill(0); key?.fill(0); i.bearer.fill(0) }
}
function eventFromArray(raw: unknown): Event {
  array(raw, 7)
  const [id, key, created_at, kind, tags, content, sig] = raw
  check(hex(id) && pubkey(key) && integer(created_at) && integer(kind) && typeof sig === 'string' && SIG.test(sig))
  check(typeof content === 'string' && Array.isArray(tags) && tags.length <= 8)
  for (const tag of tags) check(Array.isArray(tag) && tag.length <= 4 && tag.every(s => typeof s === 'string' && s.length <= 256))
  const event: Event = { id, pubkey: key, created_at, kind, tags, content, sig }
  check(verifyEventUncached(event))
  return event
}
function nested(raw: unknown): Event {
  check(JSON.stringify(raw).length <= 4096 && utf8.encode(JSON.stringify(raw)).length <= 4096)
  return eventFromArray(raw)
}
function eventArray(e: Event): unknown[] { return [e.id, e.pubkey, e.created_at, e.kind, e.tags, e.content, e.sig] }
function outer(raw: string): Event {
  const value = parse(raw, 32768)
  check(typeof value === 'object' && value !== null && !Array.isArray(value))
  const e = value as Record<string, unknown>
  const keys = ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig']
  check(Object.keys(e).length === keys.length && keys.every(k => Object.hasOwn(e, k)))
  check(typeof e.content === 'string' && e.content.length === MLS_ADMISSION_CIPHERTEXT_CHARACTERS && /^[A-Za-z0-9+/]+={0,2}$/.test(e.content))
  check(base64.encode(base64.decode(e.content)) === e.content)
  return eventFromArray(keys.map(k => e[k]))
}
function credential(raw: unknown, account: string, device: string, expiry: number, now: number): Event {
  const e = nested(raw)
  check(e.kind === 20460 && e.pubkey === account && e.content === '' && e.created_at <= now + 30)
  const tags = new Map<string, string>()
  for (const tag of e.tags) {
    check(tag.length === 2 && ['d', 'scope', 'device', 'expiration', 'label', 'seal'].includes(tag[0]) && !tags.has(tag[0]))
    tags.set(tag[0], tag[1])
  }
  check(tags.get('d') === account && tags.get('scope') === 'person' && tags.get('device') === device && pubkey(device))
  const expiration = tags.get('expiration')
  check(expiration !== undefined && DECIMAL.test(expiration) && integer(Number(expiration)))
  const end = Number(expiration)
  check(end > now && end >= expiry && end - e.created_at <= 30 * 86400 && end - now <= 30 * 86400)
  check(!tags.has('label') || tags.get('label')!.length <= 64)
  check(!tags.has('seal') || pubkey(tags.get('seal')))
  return e
}
function checkNow(now: number): void { check(integer(now) && now <= Number.MAX_SAFE_INTEGER - 7 * 86400 - 30) }
function requestCore(raw: unknown, i: PublicInvitation, now: number): unknown[] {
  checkNow(now); array(raw, 17)
  check(raw[0] === 4 && raw[1] === REQUEST && raw[2] === i.id && raw[3] === i.root && pubkey(raw[4]))
  for (const index of [5, 6, 12]) check(hex(raw[index]))
  for (const index of [7, 8, 9, 10]) check(pubkey(raw[index]))
  check(typeof raw[13] === 'string' && DECIMAL.test(raw[13]) && raw[13].length <= 20 && BigInt(raw[13]) <= 0xffffffffffffffffn)
  time(raw[14]); time(raw[15]); time(raw[16])
  check(raw[16] === raw[15] + 90 && now < raw[16] && raw[15] <= now + 30)
  check(raw[14] > raw[16] && raw[14] - raw[15] <= 7 * 86400)
  credential(raw[11], raw[7] as string, raw[9] as string, raw[14], now)
  return raw
}
function proofSpecs(core: unknown[]): { pubkey: string; event: UnsignedEvent }[] {
  const request = core[1] === REQUEST
  const keys = request ? [core[7], core[8], core[9]] : [core[15], core[16]]
  const labels = request ? [ACCOUNT, BROWSER, ENGINE] : [KEEPER_ACCOUNT, KEEPER_DEVICE]
  return keys.map((key, n) => ({ pubkey: key as string,
    event: { kind: request ? 20466 : 20467, created_at: core[request ? 15 : 25] as number,
      tags: [['t', labels[n]]], content: JSON.stringify([4, digest(core)]) } }))
}
function checkProofs(raw: unknown, core: unknown[]): unknown[] {
  const specs = proofSpecs(core)
  array(raw, specs.length)
  for (let n = 0; n < specs.length; n++) {
    const e = nested(raw[n]), s = specs[n]
    check(e.pubkey === s.pubkey && e.kind === s.event.kind && e.created_at === s.event.created_at && same(e.tags, s.event.tags) && e.content === s.event.content)
  }
  return raw
}
function wrapper(core: unknown[], proofs: unknown[]): string {
  const empty = JSON.stringify([4, core, proofs, ''])
  const length = utf8.encode(empty).length
  check(length <= MLS_ADMISSION_PLAINTEXT_BYTES)
  const padded = JSON.stringify([4, core, proofs, '0'.repeat(MLS_ADMISSION_PLAINTEXT_BYTES - length)])
  check(utf8.encode(padded).length === MLS_ADMISSION_PLAINTEXT_BYTES)
  return padded
}
function unwrap(raw: string): { core: unknown[]; proofs: unknown[] } {
  check(utf8.encode(raw).length === MLS_ADMISSION_PLAINTEXT_BYTES)
  const value = parse(raw, MLS_ADMISSION_PLAINTEXT_BYTES)
  array(value, 4)
  check(value[0] === 4 && Array.isArray(value[1]) && Array.isArray(value[2]) && typeof value[3] === 'string' && /^0*$/.test(value[3]))
  check(wrapper(value[1], value[2]) === raw)
  return { core: value[1], proofs: value[2] }
}
function requestTags(i: PublicInvitation, deadline: number): string[][] {
  return [['d', i.id], ['p', i.root], ['expiration', String(deadline)]]
}
function requestOuter(e: Event, core: unknown[], i: PublicInvitation): void {
  check(e.kind === 20466 && e.pubkey === core[4] && e.created_at === core[15] && same(e.tags, requestTags(i, core[16] as number)))
}
function retainRequest(handle: VerifiedMlsAdmissionRequest, now: number): RequestEvidence {
  check(typeof handle === 'object' && handle !== null)
  const value = requests.get(handle)
  check(value)
  const i = { root: value.root, id: value.invitationId }
  requestCore(value.core, i, now); requestOuter(value.event, value.core, i)
  return value
}
function answerCore(raw: unknown, request: RequestEvidence, now: number): unknown[] {
  checkNow(now); check(Array.isArray(raw))
  const q = request.core
  check(raw[0] === 4 && raw[1] === ANSWER && (raw[2] === 'allow' || raw[2] === 'deny'))
  check(raw[3] === q[2] && raw[4] === q[3] && raw[5] === request.event.id && raw[6] === request.digest && raw[7] === q[5] && raw[8] === q[6])
  const allow = raw[2] === 'allow', created = allow ? 25 : 9, deadline = allow ? 26 : 10
  array(raw, allow ? 27 : 11)
  time(raw[created]); time(raw[deadline])
  check(raw[deadline] === q[16] && (q[15] as number) <= raw[created] && raw[created] < raw[deadline] && now < raw[deadline] && raw[created] <= now + 30)
  if (allow) {
    for (const [a, b] of [[9, 7], [10, 8], [11, 9], [12, 10], [13, 12], [14, 13]]) check(raw[a] === q[b])
    for (const index of [15, 16, 18]) check(pubkey(raw[index]))
    for (const index of [19, 20, 21, 22]) check(hex(raw[index]))
    check(raw[19] === q[12] && raw[20] === q[12])
    time(raw[23]); time(raw[24])
    check(raw[23] > (raw[26] as number) && raw[23] <= (q[14] as number) && raw[23] <= raw[24] && raw[24] > now)
    credential(raw[17], raw[15] as string, raw[16] as string, raw[23], now)
  }
  return raw
}
function answerTags(request: RequestEvidence): string[][] {
  return [['p', request.event.pubkey], ['e', request.event.id], ['expiration', String(request.core[16])]]
}
function answerOuter(e: Event, core: unknown[], request: RequestEvidence): void {
  check(e.kind === 20467 && e.pubkey === request.core[3] && e.created_at === core[core[2] === 'allow' ? 25 : 9] && same(e.tags, answerTags(request)))
}

/** Templates only. Account/device signers remain caller-owned and settle under
 * the application's actual custody. Returned templates never confer authority.
 * core is the exact canonical request array or, with request, Allow array. */
export function mlsAdmissionProofTemplatesV4(opts: {
  fragment: string; core: string; now: number; request?: VerifiedMlsAdmissionRequest
}): { pubkey: string; event: UnsignedEvent }[] {
  const i = invitation(opts.fragment)
  try {
    const value = parse(opts.core, MLS_ADMISSION_PLAINTEXT_BYTES)
    const core = opts.request ? answerCore(value, retainRequest(opts.request, opts.now), opts.now) : requestCore(value, i, opts.now)
    if (opts.request) {
      const request = retainRequest(opts.request, opts.now)
      check(core[2] === 'allow' && i.root === request.root && i.id === request.invitationId)
    }
    return proofSpecs(core)
  } finally { i.bearer.fill(0) }
}
/** proofs is canonical JSON of the three seven-field signed proof arrays. */
export function encodeMlsAdmissionRequestV4(opts: {
  fragment: string; core: string; proofs: string; requestSecretKey: Uint8Array; now: number
}): string {
  const i = invitation(opts.fragment)
  try {
    const core = requestCore(parse(opts.core, MLS_ADMISSION_PLAINTEXT_BYTES), i, opts.now)
    const proofs = checkProofs(parse(opts.proofs, MLS_ADMISSION_PLAINTEXT_BYTES), core)
    const body = wrapper(core, proofs)
    return secret(opts.requestSecretKey, sk => {
      check(getPublicKey(sk) === core[4])
      const content = withKey(i, sk, i.root, REQUEST_KEY, key => nip44.v2.encrypt(body, key))
      const e = finalizeEvent({ kind: 20466, created_at: core[15] as number, tags: requestTags(i, core[16] as number), content }, sk)
      check(content.length === MLS_ADMISSION_CIPHERTEXT_CHARACTERS)
      return JSON.stringify({ id: e.id, pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content, sig: e.sig })
    })
  } finally { i.bearer.fill(0) }
}
/** Either endpoint may decode its exact request; only this decoder issues the
 * nominal result, after fresh outer/inner checks. Caller secrets are not kept. */
export function decodeMlsAdmissionRequestV4(opts: {
  fragment: string; event: string; localSecretKey: Uint8Array; side: 'root' | 'joiner'; now: number
}): VerifiedMlsAdmissionRequest {
  const i = invitation(opts.fragment)
  try {
    checkNow(opts.now); const e = outer(opts.event)
    check(e.kind === 20466 && (opts.side === 'root' || opts.side === 'joiner'))
    check(integer(e.created_at + 90) && e.created_at <= opts.now + 30 && opts.now < e.created_at + 90 && same(e.tags, requestTags(i, e.created_at + 90)))
    return secret(opts.localSecretKey, sk => {
      check(getPublicKey(sk) === (opts.side === 'root' ? i.root : e.pubkey))
      const body = withKey(i, sk, opts.side === 'root' ? e.pubkey : i.root, REQUEST_KEY, key => nip44.v2.decrypt(e.content, key))
      const { core: raw, proofs } = unwrap(body)
      const core = requestCore(raw, i, opts.now)
      requestOuter(e, core, i); checkProofs(proofs, core)
      const handle = Object.freeze(Object.create(null)) as VerifiedMlsAdmissionRequest
      requests.set(handle, { root: i.root, invitationId: i.id, core, digest: digest(core), event: e })
      return handle
    })
  } finally { i.bearer.fill(0) }
}
/** Returned strings are copies of evidence, not a rehydration format. */
export function readMlsAdmissionRequestV4(handle: VerifiedMlsAdmissionRequest): Readonly<{
  core: string; digest: string; eventId: string
}> {
  const value = requests.get(handle)
  check(value)
  return Object.freeze({ core: JSON.stringify(value.core), digest: value.digest, eventId: value.event.id })
}
/** Root correlation and signed keeper consent only. This encoder cannot attest
 * current keeper role; actual vault/box custody and fresh checks stay external. */
export function encodeMlsAdmissionAnswerV4(opts: {
  fragment: string; request: VerifiedMlsAdmissionRequest; core: string; proofs: string; rootSecretKey: Uint8Array; now: number
}): string {
  const request = retainRequest(opts.request, opts.now), i = invitation(opts.fragment)
  try {
    check(i.root === request.root && i.id === request.invitationId)
    const core = answerCore(parse(opts.core, MLS_ADMISSION_PLAINTEXT_BYTES), request, opts.now)
    const raw = parse(opts.proofs, MLS_ADMISSION_PLAINTEXT_BYTES)
    const proofs = core[2] === 'allow' ? checkProofs(raw, core) : (array(raw, 0), raw)
    const body = wrapper(core, proofs)
    return secret(opts.rootSecretKey, sk => {
      check(getPublicKey(sk) === i.root)
      const content = withKey(i, sk, request.event.pubkey, ANSWER_KEY, key => nip44.v2.encrypt(body, key))
      const e = finalizeEvent({ kind: 20467, created_at: core[core[2] === 'allow' ? 25 : 9] as number, tags: answerTags(request), content }, sk)
      check(content.length === MLS_ADMISSION_CIPHERTEXT_CHARACTERS)
      return JSON.stringify({ id: e.id, pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content, sig: e.sig })
    })
  } finally { i.bearer.fill(0) }
}
export function decodeMlsAdmissionAnswerV4(opts: {
  fragment: string; request: VerifiedMlsAdmissionRequest; event: string; requestSecretKey: Uint8Array; now: number
}): VerifiedAdmissionAnswer {
  const request = retainRequest(opts.request, opts.now), i = invitation(opts.fragment)
  try {
    check(i.root === request.root && i.id === request.invitationId)
    const e = outer(opts.event)
    check(e.kind === 20467 && e.pubkey === i.root && same(e.tags, answerTags(request)))
    check((request.core[15] as number) <= e.created_at && e.created_at < (request.core[16] as number) && e.created_at <= opts.now + 30)
    return secret(opts.requestSecretKey, sk => {
      check(getPublicKey(sk) === request.event.pubkey)
      const body = withKey(i, sk, i.root, ANSWER_KEY, key => nip44.v2.decrypt(e.content, key))
      const { core: raw, proofs } = unwrap(body)
      const core = answerCore(raw, request, opts.now)
      answerOuter(e, core, request)
      if (core[2] === 'allow') checkProofs(proofs, core)
      else array(proofs, 0)
      const handle = Object.freeze(Object.create(null)) as VerifiedAdmissionAnswer
      answers.set(handle, { core, digest: digest(core), event: e, requestEventId: request.event.id })
      return handle
    })
  } finally { i.bearer.fill(0) }
}
/** Cryptographic evidence only: no usable capability, child or admission. The
 * application must obtain current role witness and consume the operation once. */
export function readMlsAdmissionAnswerV4(handle: VerifiedAdmissionAnswer): Readonly<{
  decision: 'allow' | 'deny'; core: string; digest: string; eventId: string; requestEventId: string
}> {
  const value = answers.get(handle)
  check(value)
  return Object.freeze({ decision: value.core[2] as 'allow' | 'deny', core: JSON.stringify(value.core), digest: value.digest,
    eventId: value.event.id, requestEventId: value.requestEventId })
}
