import { hkdf } from '@noble/hashes/hkdf'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils'
import { schnorr } from '@noble/curves/secp256k1.js'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure'
import { hexEquals, normaliseHex } from './hex.js'
import { KINDS } from './kinds.js'
import { deriveRoom } from './room.js'
import { verifyDeviceCredential } from './credential.js'
import { evaluateAccess } from './access.js'
import { verifyEventUncached } from './verify.js'
import { withExpiration } from './expiration.js'
import { epochCommitment } from './epoch-commit.js'
import type { RelayTransport } from './transport.js'
import type { DeviceCredential, KindredProof, RoomPolicy } from './types.js'
import type { MemberEpochSource } from './member-epoch.js'

/**
 * Room epochs: how a member is removed.
 *
 * A room's traffic key is derived from its secret, and everybody who was
 * ever admitted holds it. Link rotation retires the rendezvous and nothing
 * else: a departed collaborator, or a leaked agent key, reads the room for
 * as long as the room lives. The only thing that ends that is a new key
 * that the departed party is not given, and that is an epoch.
 *
 * Epoch 0 is the room as it has always been: the id and key `deriveRoom`
 * produces from the secret in the link, byte for byte. Every later epoch is
 * a fresh 32-byte secret from which its own id and key are derived, under
 * info strings that name the epoch number. The roster, the chat and its
 * channels, the descriptor and the media keys all move to the new epoch's
 * id and key together; the *room id* - what a credential binds to, what a
 * signal names, what a forwarder is given - does not move, because it is
 * the room's identity rather than its key.
 *
 * The move is announced by a rekey event: durable, addressed by the public
 * room id, numbered in a tag, signed by the room's authority (the root
 * inviter pinned in the link), and carrying the new secret sealed to each
 * remaining device. Its body is encrypted to the epoch being left, so a
 * member at that epoch reads it and moves, and a relay reads nothing but a
 * number. A member that missed one asks the authority for the current
 * epoch, proving who it is with its device credential and that it was
 * admitted with a proof under the room key, and the authority answers
 * everybody except the removed.
 *
 * The admission proof is what keeps the desk from being a back door. The
 * room id and the authority's pubkey are public: both ride in the clear on
 * every rekey event. A device credential is self-issued by whichever
 * participant key signs it. So a request carrying only a credential proves
 * nothing a stranger reading the relay could not produce, and in an open
 * room the desk would hand that stranger the current epoch's secret, which
 * opens the roster and the chat. The epoch-0 room key is the one thing the
 * link hands out and nothing else does, so a MAC under a key derived from
 * it is proof of having been admitted, and the desk demands one.
 *
 * Copies are sealed to the *device* pubkey, not the participant's, because
 * the device key is the one every session holds in memory: a participant
 * key may live in a browser extension or a bunker that signs and does
 * nothing else, and the identity surface is deliberately a pubkey and one
 * `signEvent` (see `identity.ts`). The participant is what a rekey names -
 * the removed set, the refusal - and the device credential is how a device
 * proves which participant it speaks for when it asks.
 */

export const EPOCH_ID_INFO = 'kithmoot/v1/epoch-id'
export const EPOCH_KEY_INFO = 'kithmoot/v1/epoch-key'
const EPOCH_MAX_AGE_SECONDS = 90
const DEFAULT_TIMEOUT_MS = 30_000
const DEFAULT_RETRY_MS = 2_000
/** A room that has been rekeyed more times than this has a problem that is
 *  not this module's to solve. Bounds the tag a client will parse. */
export const MAX_EPOCH = 1_000_000
/**
 * HKDF info string for the key an epoch request's admission proof is made
 * under. Its own domain, like the media key's: a proof key that was the
 * room key would put the room key itself into a MAC on every request, and
 * a key that is only the epoch-request key opens nothing else if it leaks.
 */
export const EPOCH_REQUEST_KEY_INFO = 'kithmoot/v1/epoch-request-key'

/** One epoch of a room. Epoch 0's secret is the room secret itself. */
export interface RoomEpoch {
  epoch: number
  secret: Uint8Array
}

/** What the roster, chat and descriptor ride under in one epoch. */
export interface EpochKeys {
  epoch: number
  /** The `d` tag root. The room id in epoch 0. */
  id: string
  /** The cipher key. The room key in epoch 0. */
  key: Uint8Array
}

const HEX64 = /^[0-9a-f]{64}$/i

function require32(bytes: Uint8Array, what: string): void {
  if (bytes.length !== 32) throw new Error(`${what} must be 32 bytes`)
}

function requireHex32(value: string, what: string): string {
  if (!HEX64.test(value)) throw new Error(`${what} must be 32-byte hex`)
  return normaliseHex(value)
}

function requireEpochNumber(epoch: number): number {
  if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > MAX_EPOCH) throw new Error('epoch must be a small non-negative integer')
  return epoch
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** A fresh secret for the next epoch. */
export function generateEpochSecret(): Uint8Array {
  return randomBytes(32)
}

/**
 * The id and key a room's traffic rides under in `epoch`.
 *
 * Epoch 0 is exactly `deriveRoom(secret)`, so a room that has never been
 * rekeyed is byte-identical on the wire to one from before epochs existed.
 * Every later epoch expands its own secret under info strings that carry
 * the epoch number, so the same secret at two numbers - which a correct
 * authority never produces - would still derive two different keys.
 */
export function deriveEpoch(epoch: RoomEpoch): EpochKeys {
  require32(epoch.secret, 'epoch secret')
  const n = requireEpochNumber(epoch.epoch)
  if (n === 0) {
    const { roomId, roomKey } = deriveRoom(epoch.secret)
    return { epoch: 0, id: roomId, key: roomKey }
  }
  return {
    epoch: n,
    id: hex(hkdf(sha256, epoch.secret, undefined, `${EPOCH_ID_INFO}/${n}`, 32)),
    key: hkdf(sha256, epoch.secret, undefined, `${EPOCH_KEY_INFO}/${n}`, 32),
  }
}

// ---------------------------------------------------------------------------
// The rekey event
// ---------------------------------------------------------------------------

interface SealedSecret {
  v: 1
  secret: string
}

interface RekeyBody {
  v: 1
  epoch: number
  removed: string[]
  by?: string
  closed?: true
  /** `epochCommitment(roomId, epoch, secret)`: lets a member hand this epoch
   *  on and the requester check it. Absent from a rekey written without it. */
  commit?: string
  /** Device pubkey to a NIP-44 envelope, from the authority to that device,
   *  carrying the new secret. Inside the body, so who was kept is known
   *  only to the epoch being left. */
  keys: Record<string, string>
}

export interface EncodeRekeyOptions {
  roomId: string
  /** The room's authority: the root inviter key. Only it may rekey. */
  authoritySk: Uint8Array
  /** The epoch being left. Its key seals the body. */
  current: EpochKeys
  /** The epoch being entered. Must be `current.epoch + 1`. */
  next: RoomEpoch
  /** Devices to seal the new secret for. Everybody still in the room,
   *  except the removed participants' devices. */
  recipients: string[]
  /** Participants removed at this step. Empty on a rekey that only turns
   *  the key over. */
  removed: string[]
  /** The admin who asked, when one did. */
  by?: string
  /** True when the room is being closed: nobody is kept, and the event
   *  says so rather than leaving everybody to wonder. */
  closed?: boolean
  /** Write the epoch commitment into the body, so any current member can
   *  bring a device that missed this rekey up to date (see
   *  `member-epoch.ts`). Omitted, the event is byte-identical to before. */
  commit?: boolean
  now: number
  /** A conference room's end, in unix seconds: the event carries it as a
   *  NIP-40 expiration (see `withExpiration`). Omit for a room with no end. */
  expiresAt?: number
}

/** Announce the next epoch. See the module comment for what this is. */
export function encodeRekeyEvent(opts: EncodeRekeyOptions): Event {
  require32(opts.authoritySk, 'authority secret key')
  require32(opts.next.secret, 'epoch secret')
  const roomId = requireHex32(opts.roomId, 'room id')
  const epoch = requireEpochNumber(opts.next.epoch)
  if (epoch !== opts.current.epoch + 1) throw new Error('a rekey moves the room forward by exactly one epoch')
  const removed = [...new Set(opts.removed.map((p) => requireHex32(p, 'removed participant')))].sort()
  const keys: Record<string, string> = {}
  const sealed: SealedSecret = { v: 1, secret: base64urlnopad.encode(opts.next.secret) }
  const plaintext = JSON.stringify(sealed)
  for (const raw of opts.closed ? [] : opts.recipients) {
    const device = requireHex32(raw, 'recipient device')
    keys[device] = nip44.v2.encrypt(plaintext, nip44.v2.utils.getConversationKey(opts.authoritySk, device))
  }
  const body: RekeyBody = {
    v: 1,
    epoch,
    removed,
    ...(opts.by !== undefined ? { by: requireHex32(opts.by, 'admin') } : {}),
    ...(opts.closed ? { closed: true } : {}),
    ...(opts.commit ? { commit: epochCommitment(roomId, epoch, opts.next.secret) } : {}),
    keys,
  }
  return finalizeEvent(
    {
      kind: KINDS.ROOM_REKEY,
      created_at: opts.now,
      tags: withExpiration([
        ['d', roomId],
        ['epoch', String(epoch)],
      ], opts.expiresAt),
      content: nip44.v2.encrypt(JSON.stringify(body), opts.current.key),
    },
    opts.authoritySk,
  )
}

/** What a rekey says, once read. */
export interface RekeyNotice {
  epoch: number
  removed: string[]
  by?: string
  closed: boolean
  /** The new secret, when a copy was sealed for this device. Absent for a
   *  device that was removed, or that was not in the room when the
   *  authority rekeyed. */
  secret?: Uint8Array
  /** True for a current-state grant, whose removed list is cumulative.
   *  It synchronises this session; it does not describe a new removal. */
  catchUp?: true
  /** The authority's clock when it rekeyed, or receipt time for catch-up. */
  at: number
}

export interface PeekRekeyOptions {
  roomId: string
  /** The authority pubkey: the root inviter pinned in the link. */
  authority: string
}

/**
 * The epoch a rekey announces, checking everything that does not need a
 * key: kind, room, signer, signature and the epoch tag. What a client uses
 * to learn that the room is ahead of it before it can read why.
 */
export function peekRekeyEvent(event: Event, opts: PeekRekeyOptions): number | null {
  try {
    if (event.kind !== KINDS.ROOM_REKEY) return null
    if (!hexEquals(event.pubkey, opts.authority)) return null
    if (event.tags.find((t) => t[0] === 'd')?.[1]?.toLowerCase() !== normaliseHex(opts.roomId)) return null
    const tag = event.tags.find((t) => t[0] === 'epoch')?.[1]
    if (tag === undefined || !/^[1-9][0-9]{0,6}$/.test(tag)) return null
    const epoch = Number(tag)
    if (epoch > MAX_EPOCH) return null
    if (!verifyEventUncached(event)) return null
    return epoch
  } catch {
    return null
  }
}

export interface DecodeRekeyOptions extends PeekRekeyOptions {
  /** The epoch this device is at. A rekey is readable only from the epoch
   *  it leaves, and only accepted when it moves forward. */
  current: EpochKeys
  /** This device's key, to open its own copy. */
  deviceSk: Uint8Array
}

/**
 * Read a rekey. Null for anything that does not check out, and for a rekey
 * this device cannot read from where it stands: one for an epoch it is
 * already past (a replay), or one sealed to an epoch it is not at.
 */
export function decodeRekeyEvent(event: Event, opts: DecodeRekeyOptions): RekeyNotice | null {
  try {
    const epoch = peekRekeyEvent(event, opts)
    if (epoch === null || epoch !== opts.current.epoch + 1) return null
    const body = JSON.parse(nip44.v2.decrypt(event.content, opts.current.key)) as Partial<RekeyBody>
    if (body.v !== 1 || body.epoch !== epoch) return null
    if (!Array.isArray(body.removed) || !body.removed.every((p) => typeof p === 'string' && HEX64.test(p))) return null
    if (typeof body.keys !== 'object' || body.keys === null) return null
    const notice: RekeyNotice = {
      epoch,
      removed: [...new Set(body.removed.map(normaliseHex))].sort(),
      closed: body.closed === true,
      at: event.created_at,
    }
    if (typeof body.by === 'string' && HEX64.test(body.by)) notice.by = normaliseHex(body.by)
    const device = getPublicKey(opts.deviceSk)
    const mine = Object.entries(body.keys).find(([to]) => hexEquals(to, device))?.[1]
    if (typeof mine === 'string') {
      const sealed = JSON.parse(
        nip44.v2.decrypt(mine, nip44.v2.utils.getConversationKey(opts.deviceSk, event.pubkey)),
      ) as Partial<SealedSecret>
      if (sealed.v === 1 && typeof sealed.secret === 'string') {
        const secret = base64urlnopad.decode(sealed.secret)
        if (secret.length === 32) notice.secret = secret
      }
    }
    return notice
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Asking the authority for the current epoch
// ---------------------------------------------------------------------------

/**
 * The key an epoch request's admission proof is computed under: the epoch-0
 * room key, expanded under its own info string. Taken from the room key
 * rather than the room secret for the same reason the media key is: a
 * joined client holds the room key and need not keep the capability.
 */
export function deriveEpochRequestKey(roomKey: Uint8Array): Uint8Array {
  require32(roomKey, 'room key')
  return hkdf(sha256, roomKey, undefined, EPOCH_REQUEST_KEY_INFO, 32)
}

export interface EpochRequestAdmissionOptions {
  /** The epoch-0 room key: `deriveRoom(secret).roomKey`, never a later epoch's. */
  roomKey: Uint8Array
  roomId: string
  authority: string
  device: string
  /** The request event's `created_at`. */
  createdAt: number
}

/**
 * Prove, inside an epoch request, that the asking device was admitted to
 * the room.
 *
 * `HMAC-SHA256(deriveEpochRequestKey(roomKey), "kithmoot/v1/epoch-request:" +
 * roomId + ":" + authority + ":" + device + ":" + createdAt)`, as hex, with
 * the three identifiers in lower-case hex. Bound to the device and the
 * moment so that a proof lifted from one request is no use in another,
 * though the body it rides in is already sealed to the authority. Every
 * admitted device holds the epoch-0 room key, including one that has fallen
 * several epochs behind, which is exactly who asks; a removed member holds
 * it too, and is refused by name, not by this. What this refuses is the
 * stranger: somebody with the room id and the authority's pubkey off a
 * public rekey event, and no link.
 */
export function epochRequestAdmission(opts: EpochRequestAdmissionOptions): string {
  const roomId = requireHex32(opts.roomId, 'room id')
  const authority = requireHex32(opts.authority, 'authority pubkey')
  const device = requireHex32(opts.device, 'device pubkey')
  if (!Number.isSafeInteger(opts.createdAt) || opts.createdAt < 0) throw new Error('created_at must be a non-negative integer')
  const message = new TextEncoder().encode(`kithmoot/v1/epoch-request:${roomId}:${authority}:${device}:${opts.createdAt}`)
  return bytesToHex(hmac(sha256, deriveEpochRequestKey(opts.roomKey), message))
}

/** Equality that does not leak where two proofs first differ. */
function admissionEquals(presented: string, expected: string): boolean {
  const a = normaliseHex(presented)
  if (a.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ expected.charCodeAt(i)
  return diff === 0
}

interface EpochRequestBody {
  v: 1
  credential: DeviceCredential
  proof?: KindredProof
  /** `epochRequestAdmission` for this request. Required by every desk from
   *  the release that introduced it; a responder from before ignores it. */
  admission: string
}

export interface EncodeEpochRequestOptions {
  roomId: string
  authority: string
  deviceSk: Uint8Array
  /** The epoch-0 room key, which proves this device was admitted. */
  roomKey: Uint8Array
  /** Proves which participant this device speaks for. */
  credential: DeviceCredential
  proof?: KindredProof
  now: number
  /** A conference room's end, in unix seconds: the event carries it as a
   *  NIP-40 expiration (see `withExpiration`). Omit for a room with no end. */
  expiresAt?: number
}

/** Ask the authority which epoch the room is at, and for its secret. */
export function encodeEpochRequest(opts: EncodeEpochRequestOptions): Event {
  require32(opts.deviceSk, 'device secret key')
  const roomId = requireHex32(opts.roomId, 'room id')
  const authority = requireHex32(opts.authority, 'authority pubkey')
  const admission = epochRequestAdmission({
    roomKey: opts.roomKey,
    roomId,
    authority,
    device: getPublicKey(opts.deviceSk),
    createdAt: opts.now,
  })
  const body: EpochRequestBody = { v: 1, credential: opts.credential, ...(opts.proof ? { proof: opts.proof } : {}), admission }
  return finalizeEvent(
    {
      kind: KINDS.EPOCH_REQUEST,
      created_at: opts.now,
      tags: withExpiration([
        ['d', roomId],
        ['p', authority],
      ], opts.expiresAt),
      content: nip44.v2.encrypt(JSON.stringify(body), nip44.v2.utils.getConversationKey(opts.deviceSk, authority)),
    },
    opts.deviceSk,
  )
}

export interface DecodeEpochRequestOptions {
  roomId: string
  authoritySk: Uint8Array
  /** The epoch-0 room key the desk checks admission proofs against. */
  roomKey: Uint8Array
  now: number
  policy?: RoomPolicy
  /** Participants whose already-signed device credential may bridge a
   * pre-admission-proof client. Keep this narrow: a missing proof is never
   * accepted for an ordinary link holder. */
  legacyParticipants?: ReadonlySet<string>
  maxAgeSeconds?: number
}

export interface EpochRequest {
  device: string
  participant: string
  request: string
}

/** Null for anything malformed, stale, misaddressed, from a device that
 *  cannot prove which participant it speaks for in this room, or from one
 *  that cannot prove it was admitted to the room at all. */
export function decodeEpochRequest(event: Event, opts: DecodeEpochRequestOptions): EpochRequest | null {
  try {
    if (event.kind !== KINDS.EPOCH_REQUEST) return null
    if (!verifyEventUncached(event)) return null
    if (Math.abs(opts.now - event.created_at) > (opts.maxAgeSeconds ?? EPOCH_MAX_AGE_SECONDS)) return null
    if (event.tags.find((t) => t[0] === 'd')?.[1]?.toLowerCase() !== normaliseHex(opts.roomId)) return null
    const authority = getPublicKey(opts.authoritySk)
    const addressed = event.tags.find((t) => t[0] === 'p')?.[1]
    if (addressed === undefined || !hexEquals(addressed, authority)) return null
    const body = JSON.parse(
      nip44.v2.decrypt(event.content, nip44.v2.utils.getConversationKey(opts.authoritySk, event.pubkey)),
    ) as Partial<EpochRequestBody>
    if (body.v !== 1 || typeof body.credential !== 'object' || body.credential === null) return null
    const verdict = verifyDeviceCredential(body.credential, { roomId: opts.roomId, now: opts.now })
    if (!verdict.ok) return null
    if (!hexEquals(verdict.device, event.pubkey)) return null
    // Admission before policy: a stranger with no room key is turned away
    // before anything about the room's tiers is consulted. A keeper may
    // bridge its named admins from the last desktop release: their signed
    // participant identity is configured out of band, while an arbitrary
    // holder of the public room id still gets no answer.
    if (typeof body.admission === 'string') {
      const expected = epochRequestAdmission({
        roomKey: opts.roomKey,
        roomId: opts.roomId,
        authority,
        device: verdict.device,
        createdAt: event.created_at,
      })
      if (!admissionEquals(body.admission, expected)) return null
    } else if (!opts.legacyParticipants?.has(verdict.participant)) return null
    if (opts.policy) {
      const proof = body.proof && typeof body.proof === 'object' ? body.proof : undefined
      if (!evaluateAccess(opts.policy, verdict.participant, proof, opts.now, opts.roomId).admitted) return null
    }
    return { device: verdict.device, participant: verdict.participant, request: event.id }
  } catch {
    return null
  }
}

/** Why the authority would not hand an epoch over. */
export type EpochRefusal = 'removed' | 'closed'

interface EpochGrantBody {
  v: 1
  request: string
  epoch?: number
  secret?: string
  removed?: string[]
  refused?: EpochRefusal
}

export interface EncodeEpochGrantOptions {
  roomId: string
  authoritySk: Uint8Array
  device: string
  request: string
  now: number
  /** The current epoch. Omitted when refusing. */
  epoch?: RoomEpoch
  removed?: string[]
  refused?: EpochRefusal
  /** A conference room's end, in unix seconds: the event carries it as a
   *  NIP-40 expiration (see `withExpiration`). Omit for a room with no end. */
  expiresAt?: number
}

/** Answer one request: the current epoch sealed to the asking device, or a
 *  refusal it alone can read. */
export function encodeEpochGrant(opts: EncodeEpochGrantOptions): Event {
  require32(opts.authoritySk, 'authority secret key')
  const roomId = requireHex32(opts.roomId, 'room id')
  const device = requireHex32(opts.device, 'device pubkey')
  const request = requireHex32(opts.request, 'request id')
  const body: EpochGrantBody = { v: 1, request }
  if (opts.refused) {
    body.refused = opts.refused
  } else {
    if (!opts.epoch) throw new Error('a grant carries an epoch or a refusal')
    body.epoch = requireEpochNumber(opts.epoch.epoch)
    if (body.epoch > 0) {
      require32(opts.epoch.secret, 'epoch secret')
      body.secret = base64urlnopad.encode(opts.epoch.secret)
    }
    body.removed = [...new Set((opts.removed ?? []).map((p) => requireHex32(p, 'removed participant')))].sort()
  }
  return finalizeEvent(
    {
      kind: KINDS.EPOCH_GRANT,
      created_at: opts.now,
      tags: withExpiration([
        ['d', roomId],
        ['p', device],
      ], opts.expiresAt),
      content: nip44.v2.encrypt(JSON.stringify(body), nip44.v2.utils.getConversationKey(opts.authoritySk, device)),
    },
    opts.authoritySk,
  )
}

export interface DecodeEpochGrantOptions {
  roomId: string
  authority: string
  deviceSk: Uint8Array
  request: string
  now: number
  maxAgeSeconds?: number
}

export type EpochGrant =
  | {
      epoch: RoomEpoch | { epoch: 0 }
      removed: string[]
      /** Present on a member's answer through `requestRoomEpoch({ members })`:
       *  the epochs it carried between the requester's and `epoch`. See
       *  `MemberEpochGrant.passed`. The authority's own answer has none. */
      passed?: RoomEpoch[]
      refused?: undefined
    }
  | { refused: EpochRefusal }

/** Read the authority's answer to this device's own request. Null for
 *  anything else. Note a grant for epoch 0 carries no secret: the room has
 *  never been rekeyed, and the requester already holds what it needs. */
export function decodeEpochGrant(event: Event, opts: DecodeEpochGrantOptions): EpochGrant | null {
  try {
    if (event.kind !== KINDS.EPOCH_GRANT) return null
    if (!hexEquals(event.pubkey, opts.authority)) return null
    if (!verifyEventUncached(event)) return null
    if (Math.abs(opts.now - event.created_at) > (opts.maxAgeSeconds ?? EPOCH_MAX_AGE_SECONDS)) return null
    if (event.tags.find((t) => t[0] === 'd')?.[1]?.toLowerCase() !== normaliseHex(opts.roomId)) return null
    const device = getPublicKey(opts.deviceSk)
    const addressed = event.tags.find((t) => t[0] === 'p')?.[1]
    if (addressed === undefined || !hexEquals(addressed, device)) return null
    const body = JSON.parse(
      nip44.v2.decrypt(event.content, nip44.v2.utils.getConversationKey(opts.deviceSk, event.pubkey)),
    ) as Partial<EpochGrantBody>
    if (body.v !== 1 || typeof body.request !== 'string' || !hexEquals(body.request, opts.request)) return null
    if (body.refused === 'removed' || body.refused === 'closed') return { refused: body.refused }
    if (!Number.isSafeInteger(body.epoch) || (body.epoch as number) < 0 || (body.epoch as number) > MAX_EPOCH) return null
    const removed = Array.isArray(body.removed)
      ? [...new Set(body.removed.filter((p): p is string => typeof p === 'string' && HEX64.test(p)).map(normaliseHex))].sort()
      : []
    if (body.epoch === 0) return { epoch: { epoch: 0 }, removed }
    if (typeof body.secret !== 'string') return null
    const secret = base64urlnopad.decode(body.secret)
    if (secret.length !== 32) return null
    return { epoch: { epoch: body.epoch as number, secret }, removed }
  } catch {
    return null
  }
}

export interface HostRoomEpochOptions {
  transport: RelayTransport
  roomId: string
  authoritySk: Uint8Array
  /** The epoch-0 room key: what a request has to prove it holds. */
  roomKey: Uint8Array
  /** Where the room is now. Asked on every request, because it moves. */
  current: () => RoomEpoch
  /** Who has been removed. Asked on every request, for the same reason. */
  removed: () => ReadonlySet<string>
  /** True once the room has been closed: every request is refused. */
  closed?: () => boolean
  policy?: RoomPolicy
  legacyParticipants?: ReadonlySet<string>
  now?: () => number
  onGranted?: (request: EpochRequest) => void
  onRefused?: (request: EpochRequest, why: EpochRefusal) => void
  /** A conference room's end: every grant carries it as an expiration. */
  expiresAt?: number
}

/**
 * Answer epoch requests for as long as the handle is open. What a keeper
 * runs beside its invitation desk: a member arriving, or returning, after
 * a rekey is handed the current epoch on proof of who it is and that it was
 * admitted, and a removed participant is told no. This is where removal is
 * enforced against the link: the link still admits its holder to the room's
 * *secret*, which opens epoch 0 and nothing after it. A request with no
 * admission proof, or one made under some other key, is not answered at
 * all: a stranger learns nothing, not even that a desk is here.
 */
export function hostRoomEpoch(opts: HostRoomEpochOptions): { close(): void } {
  require32(opts.authoritySk, 'authority secret key')
  require32(opts.roomKey, 'room key')
  const roomId = requireHex32(opts.roomId, 'room id')
  const authority = getPublicKey(opts.authoritySk)
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000))
  const answered = new Set<string>()
  let closed = false
  const unsub = opts.transport.subscribe(
    [{ kinds: [KINDS.EPOCH_REQUEST], '#d': [roomId], '#p': [authority] }],
    (event) => {
      if (closed) return
      const request = decodeEpochRequest(event, {
        roomId,
        authoritySk: opts.authoritySk,
        roomKey: opts.roomKey,
        now: now(),
        policy: opts.policy,
        legacyParticipants: opts.legacyParticipants,
      })
      if (!request || answered.has(request.request)) return
      answered.add(request.request)
      if (answered.size > 256) answered.delete(answered.values().next().value!)
      let refused: EpochRefusal | undefined
      if (opts.closed?.()) refused = 'closed'
      else if (opts.removed().has(request.participant)) refused = 'removed'
      let grant: Event
      try {
        grant = refused
          ? encodeEpochGrant({ roomId, authoritySk: opts.authoritySk, device: request.device, request: request.request, now: now(), refused, expiresAt: opts.expiresAt })
          : encodeEpochGrant({
              roomId,
              authoritySk: opts.authoritySk,
              device: request.device,
              request: request.request,
              now: now(),
              epoch: opts.current(),
              removed: [...opts.removed()],
              expiresAt: opts.expiresAt,
            })
      } catch {
        return
      }
      opts.transport.publish(grant).catch(() => {})
      if (refused) opts.onRefused?.(request, refused)
      else opts.onGranted?.(request)
    },
  )
  return {
    close() {
      if (closed) return
      closed = true
      unsub()
    },
  }
}

export interface RequestRoomEpochOptions {
  transport: RelayTransport
  roomId: string
  authority: string
  deviceSk: Uint8Array
  /** The epoch-0 room key, which proves this device was admitted. */
  roomKey: Uint8Array
  credential: DeviceCredential
  proof?: KindredProof
  now?: () => number
  timeoutMs?: number
  retryMs?: number
  /** A conference room's end: the request carries it as an expiration. */
  expiresAt?: number
  /** Ask the room's current members too (`memberEpochSource`): the first
   *  answer that checks out, the authority's or a member's, settles it. */
  members?: MemberEpochSource
}

/** Thrown when the authority answered, and the answer was no. */
export class EpochRefusedError extends Error {
  readonly refused: EpochRefusal
  constructor(refused: EpochRefusal) {
    super(refused === 'removed' ? 'you were removed from this room' : 'this room has been closed')
    this.name = 'EpochRefusedError'
    this.refused = refused
  }
}

/** Ask the authority where the room is, and wait for the answer. Rejects
 *  with `EpochRefusedError` on a refusal, and with a plain error when
 *  nobody answers inside the timeout. */
export function requestRoomEpoch(opts: RequestRoomEpochOptions): Promise<Exclude<EpochGrant, { refused: EpochRefusal }>> {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000))
  const roomId = requireHex32(opts.roomId, 'room id')
  const device = getPublicKey(opts.deviceSk)
  const request = encodeEpochRequest({
    roomId,
    authority: opts.authority,
    deviceSk: opts.deviceSk,
    roomKey: opts.roomKey,
    credential: opts.credential,
    proof: opts.proof,
    now: now(),
    expiresAt: opts.expiresAt,
  })
  return new Promise((resolve, reject) => {
    let settled = false
    let retry: ReturnType<typeof setInterval> | undefined
    let expiry: ReturnType<typeof setTimeout> | undefined
    let unsub = () => {}
    let stopMembers = () => {}
    const finish = (settle: () => void): void => {
      if (settled) return
      settled = true
      if (retry !== undefined) clearInterval(retry)
      if (expiry !== undefined) clearTimeout(expiry)
      unsub()
      stopMembers()
      settle()
    }
    unsub = opts.transport.subscribe([{ kinds: [KINDS.EPOCH_GRANT], '#d': [roomId], '#p': [device] }], (event) => {
      const grant = decodeEpochGrant(event, { roomId, authority: opts.authority, deviceSk: opts.deviceSk, request: request.id, now: now() })
      if (!grant) return
      if (grant.refused) finish(() => reject(new EpochRefusedError(grant.refused)))
      else finish(() => resolve(grant))
    })
    if (settled) unsub()
    if (opts.members && !settled) {
      stopMembers = opts.members.start((grant) => finish(() => resolve(grant)))
      if (settled) stopMembers()
    }
    const ask = (): void => {
      if (!settled) opts.transport.publish(request).catch(() => {})
    }
    expiry = setTimeout(
      () => finish(() => reject(new Error('the room has moved to a newer epoch and its keeper is not answering'))),
      opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    )
    ;(expiry as unknown as { unref?: () => void }).unref?.()
    retry = setInterval(ask, opts.retryMs ?? DEFAULT_RETRY_MS)
    ;(retry as unknown as { unref?: () => void }).unref?.()
    ask()
  })
}

// ---------------------------------------------------------------------------
// The admin list
// ---------------------------------------------------------------------------

function adminsMessage(roomId: string, epoch: number, admins: string[]): Uint8Array {
  return sha256(new TextEncoder().encode(`kithmoot/v1/admins:${roomId}:${epoch}:${admins.join(',')}`))
}

/** Canonical form of an admin list: lower-case, deduplicated, sorted. */
export function canonicalAdmins(admins: readonly string[]): string[] {
  return [...new Set(admins.map((a) => requireHex32(a, 'admin pubkey')))].sort()
}

export interface SignAdminsOptions {
  roomId: string
  epoch: number
  admins: readonly string[]
  authoritySk: Uint8Array
}

/**
 * Channel names a room may be told about.
 *
 * Deliberately stricter than `deriveChannel`, which accepts any string of
 * 1..64 characters because it is only doing HKDF and has no opinion. A name
 * in the REGISTRY is different: it is announced to every client, rendered as
 * a label, and handed to an agent as its thread id. So it is held to a shape
 * that survives all three without escaping, normalising or truncating -
 * lower case, digits and hyphens, opening on an alphanumeric.
 *
 * The consequence worth stating: a name is stored and compared exactly as
 * written here, so a client, an agent adapter and a relay all mean the same
 * string by it, and nothing anywhere has to guess at a canonical form.
 */
export const CHANNEL_NAME = /^[a-z0-9][a-z0-9-]{0,63}$/

/**
 * Names the registry will not carry, because the room already means
 * something by them: `agents` is the backchannel, `transcript` is what was
 * said, `minutes` is what the scribe wrote. Deriving them still works - they
 * are ordinary channels to the crypto - but announcing one as a place to
 * chat would put two different things under one name.
 */
export const RESERVED_CHANNELS: readonly string[] = ['agents', 'minutes', 'transcript']

/** Canonical form of a channel list: validated, deduplicated, sorted. */
export function canonicalChannels(channels: readonly string[]): string[] {
  for (const name of channels) {
    if (typeof name !== 'string' || !CHANNEL_NAME.test(name)) throw new Error(`bad channel name: ${String(name)}`)
    if (RESERVED_CHANNELS.includes(name)) throw new Error(`reserved channel name: ${name}`)
  }
  return [...new Set(channels)].sort()
}

function channelsMessage(roomId: string, epoch: number, channels: string[]): Uint8Array {
  return sha256(new TextEncoder().encode(`kithmoot/v1/channels:${roomId}:${epoch}:${channels.join(',')}`))
}

export interface SignChannelsOptions {
  roomId: string
  epoch: number
  channels: readonly string[]
  authoritySk: Uint8Array
}

/**
 * Sign the list of channels a room has.
 *
 * Signed by the authority and bound to the epoch for exactly the reasons the
 * admin list is: every member holds the room key, so an unsigned list is the
 * first thing a member would forge, and a list valid at one epoch must not
 * be replayable into the next. This is what settles the rule that nothing a
 * chat message says may change the structure of a room - a channel exists
 * because the authority said so, or it does not exist.
 */
export function signChannels(opts: SignChannelsOptions): string {
  require32(opts.authoritySk, 'authority secret key')
  const roomId = requireHex32(opts.roomId, 'room id')
  const channels = canonicalChannels(opts.channels)
  return bytesToHex(schnorr.sign(channelsMessage(roomId, requireEpochNumber(opts.epoch), channels), opts.authoritySk))
}

export interface VerifyChannelsOptions {
  roomId: string
  epoch: number
  channels: readonly string[]
  sig: string
  authority: string
}

/** Never throws: this runs on anything a relay hands over. */
export function verifyChannels(opts: VerifyChannelsOptions): boolean {
  try {
    const roomId = requireHex32(opts.roomId, 'room id')
    const channels = canonicalChannels(opts.channels)
    const sig = hexToBytes(opts.sig)
    if (sig.length !== 64) return false
    return schnorr.verify(
      sig,
      channelsMessage(roomId, requireEpochNumber(opts.epoch), channels),
      hexToBytes(requireHex32(opts.authority, 'authority')),
    )
  } catch {
    return false
  }
}

/**
 * Sign the list of participants who may act on the room, so a client can
 * tell a keeper's announcement from anybody else's claim: the announcement
 * rides the control channel, which every member can write to, and only the
 * authority key pinned in the link can produce this.
 */
export function signAdmins(opts: SignAdminsOptions): string {
  require32(opts.authoritySk, 'authority secret key')
  const roomId = requireHex32(opts.roomId, 'room id')
  const admins = canonicalAdmins(opts.admins)
  return bytesToHex(schnorr.sign(adminsMessage(roomId, requireEpochNumber(opts.epoch), admins), opts.authoritySk))
}

export interface VerifyAdminsOptions {
  roomId: string
  epoch: number
  admins: readonly string[]
  sig: string
  authority: string
}

export function verifyAdmins(opts: VerifyAdminsOptions): boolean {
  try {
    const roomId = requireHex32(opts.roomId, 'room id')
    const admins = canonicalAdmins(opts.admins)
    const sig = hexToBytes(opts.sig)
    if (sig.length !== 64) return false
    return schnorr.verify(sig, adminsMessage(roomId, requireEpochNumber(opts.epoch), admins), hexToBytes(requireHex32(opts.authority, 'authority')))
  } catch {
    return false
  }
}

/** Every wire-format literal this module owns (each one a kithmoot protocol string), frozen for
 *  `src/labels.test.ts`, which checks each module against its own exported
 *  list rather than scanning file text for matching comments. Pure data -
 *  adding this export changes no runtime behaviour. */
export const EPOCH_LABELS = [
  "kithmoot/v1/admins:",
  "kithmoot/v1/channels:",
  "kithmoot/v1/epoch-id",
  "kithmoot/v1/epoch-key",
  "kithmoot/v1/epoch-request-key",
  "kithmoot/v1/epoch-request:",
] as const
