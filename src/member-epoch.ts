import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { finalizeEvent, generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure'
import { hexEquals, normaliseHex } from './hex.js'
import { verifyDeviceCredential } from './credential.js'
import { evaluateAccess } from './access.js'
import { verifyEventUncached } from './verify.js'
import { withExpiration } from './expiration.js'
import { epochCommitment } from './epoch-commit.js'
import { KINDS } from './kinds.js'
import {
  MAX_EPOCH,
  deriveEpoch,
  epochRequestAdmission,
  peekRekeyEvent,
  readMemberList,
  type EpochKeys,
  type EpochRefusal,
  type RoomEpoch,
} from './epoch.js'
import type { RelayTransport } from './transport.js'
import type { DeviceCredential, KindredProof, RoomPolicy } from './types.js'

/**
 * Member-to-member epoch catch-up: any current member can bring an
 * admitted, non-removed member up to date.
 *
 * `hostRoomEpoch` answers an epoch request only where the authority's key
 * is, and the request is ephemeral, so a device that missed a rekey - a
 * phone that came back with a new device key, which no stored rekey seals
 * to - recovers only while the authority's device is online with the room
 * open. Every other member at the current epoch holds the secret and, until
 * now, could not pass it on in a form the requester could check.
 *
 * It can now, because the requester does not trust the member at all. The
 * grant carries the authority-signed rekey events from the requester's
 * epoch to the current one, and the secret of every epoch in between:
 *
 * - each rekey's signature is the authority's (`peekRekeyEvent`);
 * - each rekey decrypts under the key of the epoch before it, starting from
 *   the requester's own - and NIP-44's MAC verifies under no other key, so
 *   a decrypting rekey j+1 proves the secret offered for epoch j is the one
 *   the authority encrypted under;
 * - the last epoch, which has no successor to vouch for it, is checked
 *   against the commitment the authority wrote into its rekey body
 *   (`epochCommitment`, `encodeRekeyEvent({ commit: true })`). A last rekey
 *   with no commitment - every rekey written before this existed - is not
 *   accepted from a member: that epoch stays authority-only.
 *
 * The removed and closed facts come from the same authority-signed bodies,
 * so a member can neither hide a removal from the requester nor invent
 * one. Answerers refuse the removed and a closed room by not answering at
 * all; only the authority's refusal is something a requester can believe.
 * See `docs/member-epoch-catch-up.md` for the threat model.
 */

/** The member path's two kinds. Ephemeral, like 20468/20469: a live
 *  handshake, never a record. */
export const MEMBER_EPOCH_KINDS = {
  /** A device behind the room asking any current member for the epochs it
   *  missed. Encrypted under a key from the epoch-0 room key, so any
   *  admitted device can read it and a relay cannot. */
  REQUEST: 20471,
  /** A member's answer, signed by a one-time key made for that grant and
   *  sealed to the asking device: secrets plus the authority-signed rekeys
   *  that prove them. */
  GRANT: 20472,
} as const

/** HKDF info for the key a member epoch request's body is sealed under. */
export const MEMBER_EPOCH_REQUEST_KEY_INFO = 'kithmoot/v1/member-epoch-request-key'
/** The most epochs one member grant will carry. A device further behind
 *  than this asks the authority. */
export const MAX_MEMBER_EPOCH_CHAIN = 32
const MAX_AGE_SECONDS = 90
const DEFAULT_TIMEOUT_MS = 30_000
const DEFAULT_RETRY_MS = 4_000
const DEFAULT_JITTER_MS = 1_500
/** How long a requester waits for its relays to finish replaying the room's
 *  rekeys before it asks anyway. */
const REKEY_REPLAY_WAIT_MS = 1_500
/** Many relays refuse events much over 64 KiB. A grant inlines whole rekey
 *  events, each with a seal per device, so a long chain in a big room can
 *  pass that; a desk does not send one that would. */
const DEFAULT_MAX_GRANT_BYTES = 60_000
const HEX64 = /^[0-9a-f]{64}$/i

function requireHex32(value: string, what: string): string {
  if (typeof value !== 'string' || !HEX64.test(value)) throw new Error(`${what} must be 32-byte hex`)
  return normaliseHex(value)
}

/** Equality that does not leak where two proofs first differ. */
function constantTimeEquals(presented: string, expected: string): boolean {
  const a = normaliseHex(presented)
  if (a.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ expected.charCodeAt(i)
  return diff === 0
}

/** The key a member epoch request is sealed under: the epoch-0 room key,
 *  expanded under its own info string. */
export function deriveMemberEpochRequestKey(roomKey: Uint8Array): Uint8Array {
  if (roomKey.length !== 32) throw new Error('room key must be 32 bytes')
  return hkdf(sha256, roomKey, undefined, MEMBER_EPOCH_REQUEST_KEY_INFO, 32)
}

interface RekeyBodyView {
  v?: unknown
  epoch?: unknown
  removed?: unknown
  closed?: unknown
  commit?: unknown
  members?: unknown
}

/** What a rekey body says, read with the key of the epoch it leaves. */
export interface RekeyEvidence {
  epoch: number
  removed: string[]
  closed: boolean
  /** The epoch commitment, when the authority wrote one. */
  commit?: string
  /** The authority's member list, when it wrote one. */
  members?: string[]
}

/**
 * Read an authority-signed rekey with the key of the epoch it leaves,
 * without needing a seal of one's own. Null for anything that does not
 * check out: not the authority, not this room, not epoch `previous.epoch
 * + 1`, or not encrypted under `previous.key`. What both sides of a member
 * grant use to check the chain.
 */
export function readRekeyEvidence(event: Event, opts: { roomId: string; authority: string; previous: EpochKeys }): RekeyEvidence | null {
  try {
    const epoch = peekRekeyEvent(event, opts)
    if (epoch === null || epoch !== opts.previous.epoch + 1) return null
    const body = JSON.parse(nip44.v2.decrypt(event.content, opts.previous.key)) as RekeyBodyView
    if (body.v !== 1 || body.epoch !== epoch) return null
    if (!Array.isArray(body.removed) || !body.removed.every((p) => typeof p === 'string' && HEX64.test(p))) return null
    const evidence: RekeyEvidence = {
      epoch,
      removed: [...new Set((body.removed as string[]).map(normaliseHex))].sort(),
      closed: body.closed === true,
    }
    if (typeof body.commit === 'string' && HEX64.test(body.commit)) evidence.commit = normaliseHex(body.commit)
    const members = readMemberList(body.members)
    if (members) evidence.members = members
    return evidence
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

interface MemberEpochRequestBody {
  v: 1
  credential: DeviceCredential
  proof?: KindredProof
  /** `epochRequestAdmission` for this request, exactly as the authority's
   *  desk checks it. */
  admission: string
  /** The epoch the asking device is at. */
  have: number
}

export interface EncodeMemberEpochRequestOptions {
  roomId: string
  /** The room's authority: bound into the admission proof. */
  authority: string
  deviceSk: Uint8Array
  /** The epoch-0 room key: seals the body and makes the admission proof. */
  roomKey: Uint8Array
  credential: DeviceCredential
  proof?: KindredProof
  /** The epoch this device is at. */
  have: number
  now: number
  expiresAt?: number
}

/** Ask any current member for the epochs after `have`. */
export function encodeMemberEpochRequest(opts: EncodeMemberEpochRequestOptions): Event {
  if (opts.deviceSk.length !== 32) throw new Error('device secret key must be 32 bytes')
  const roomId = requireHex32(opts.roomId, 'room id')
  const authority = requireHex32(opts.authority, 'authority pubkey')
  if (!Number.isSafeInteger(opts.have) || opts.have < 0 || opts.have > MAX_EPOCH) throw new Error('have must be a small non-negative integer')
  const admission = epochRequestAdmission({ roomKey: opts.roomKey, roomId, authority, device: getPublicKey(opts.deviceSk), createdAt: opts.now })
  const body: MemberEpochRequestBody = {
    v: 1,
    credential: opts.credential,
    ...(opts.proof ? { proof: opts.proof } : {}),
    admission,
    have: opts.have,
  }
  return finalizeEvent(
    {
      kind: MEMBER_EPOCH_KINDS.REQUEST,
      created_at: opts.now,
      tags: withExpiration([['d', roomId]], opts.expiresAt),
      content: nip44.v2.encrypt(JSON.stringify(body), deriveMemberEpochRequestKey(opts.roomKey)),
    },
    opts.deviceSk,
  )
}

export interface DecodeMemberEpochRequestOptions {
  roomId: string
  authority: string
  roomKey: Uint8Array
  now: number
  policy?: RoomPolicy
  maxAgeSeconds?: number
}

export interface MemberEpochRequest {
  device: string
  participant: string
  request: string
  have: number
}

/** Null for anything malformed, stale, from a device that cannot prove
 *  which participant it speaks for, or that cannot prove admission. */
export function decodeMemberEpochRequest(event: Event, opts: DecodeMemberEpochRequestOptions): MemberEpochRequest | null {
  try {
    if (event.kind !== MEMBER_EPOCH_KINDS.REQUEST) return null
    if (!verifyEventUncached(event)) return null
    if (Math.abs(opts.now - event.created_at) > (opts.maxAgeSeconds ?? MAX_AGE_SECONDS)) return null
    const roomId = requireHex32(opts.roomId, 'room id')
    if (event.tags.find((t) => t[0] === 'd')?.[1]?.toLowerCase() !== roomId) return null
    const body = JSON.parse(nip44.v2.decrypt(event.content, deriveMemberEpochRequestKey(opts.roomKey))) as Partial<MemberEpochRequestBody>
    if (body.v !== 1 || typeof body.credential !== 'object' || body.credential === null) return null
    if (!Number.isSafeInteger(body.have) || (body.have as number) < 0 || (body.have as number) > MAX_EPOCH) return null
    const verdict = verifyDeviceCredential(body.credential, { roomId, now: opts.now })
    if (!verdict.ok || !hexEquals(verdict.device, event.pubkey)) return null
    if (typeof body.admission !== 'string') return null
    const expected = epochRequestAdmission({
      roomKey: opts.roomKey,
      roomId,
      authority: requireHex32(opts.authority, 'authority pubkey'),
      device: verdict.device,
      createdAt: event.created_at,
    })
    if (!constantTimeEquals(body.admission, expected)) return null
    if (opts.policy) {
      const proof = body.proof && typeof body.proof === 'object' ? body.proof : undefined
      if (!evaluateAccess(opts.policy, verdict.participant, proof, opts.now, roomId).admitted) return null
    }
    return { device: verdict.device, participant: verdict.participant, request: event.id, have: body.have as number }
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// The grant
// ---------------------------------------------------------------------------

interface MemberEpochGrantBody {
  v: 1
  request: string
  /** The epoch handed over: `have + secrets.length`. */
  epoch: number
  /** Secrets of epochs have+1 .. epoch, in order, base64url. */
  secrets: string[]
  /** The authority's rekey events for the same epochs, in order. */
  rekeys: Event[]
}

export interface EncodeMemberEpochGrantOptions {
  roomId: string
  /** The asking device. */
  device: string
  request: string
  /** Epochs have+1 .. current, in order. */
  epochs: RoomEpoch[]
  /** The authority's rekey event for each of `epochs`, in the same order. */
  rekeys: Event[]
  now: number
  expiresAt?: number
}

function plainEvent(event: Event): Event {
  const { id, pubkey, created_at, kind, tags, content, sig } = event
  return { id, pubkey, created_at, kind, tags, content, sig } as Event
}

/**
 * Answer one member epoch request with the epochs it missed.
 *
 * The grant is signed, and sealed to the asking device, by a fresh key made
 * for it alone and then dropped, not by the answering member's device key.
 * Nothing about a grant is trusted on its signer (the authority's
 * signatures are what the requester checks), so the member's key would add
 * nothing but a public line from that device to the room id in the `d` tag.
 */
export function encodeMemberEpochGrant(opts: EncodeMemberEpochGrantOptions): Event {
  const roomId = requireHex32(opts.roomId, 'room id')
  const device = requireHex32(opts.device, 'device pubkey')
  const request = requireHex32(opts.request, 'request id')
  if (opts.epochs.length < 1 || opts.epochs.length > MAX_MEMBER_EPOCH_CHAIN) throw new Error('a member grant carries 1 to 32 epochs')
  if (opts.rekeys.length !== opts.epochs.length) throw new Error('one rekey per epoch')
  for (let i = 0; i < opts.epochs.length; i += 1) {
    const e = opts.epochs[i]!
    if (e.secret.length !== 32) throw new Error('epoch secret must be 32 bytes')
    if (i > 0 && e.epoch !== opts.epochs[i - 1]!.epoch + 1) throw new Error('epochs must be consecutive')
    if (e.epoch < 1) throw new Error('a member grant never carries epoch 0')
  }
  // Drawn before anything else, so a vector records it first.
  const signerSk = generateSecretKey()
  const body: MemberEpochGrantBody = {
    v: 1,
    request,
    epoch: opts.epochs[opts.epochs.length - 1]!.epoch,
    secrets: opts.epochs.map((e) => base64urlnopad.encode(e.secret)),
    rekeys: opts.rekeys.map(plainEvent),
  }
  return finalizeEvent(
    {
      kind: MEMBER_EPOCH_KINDS.GRANT,
      created_at: opts.now,
      tags: withExpiration([
        ['d', roomId],
        ['p', device],
      ], opts.expiresAt),
      content: nip44.v2.encrypt(JSON.stringify(body), nip44.v2.utils.getConversationKey(signerSk, device)),
    },
    signerSk,
  )
}

export interface DecodeMemberEpochGrantOptions {
  roomId: string
  authority: string
  /** The asking device's key. */
  deviceSk: Uint8Array
  /** The ids of this device's own outstanding member requests. */
  requests: ReadonlySet<string>
  /** Where this device is: the chain starts from this epoch's key. */
  current: EpochKeys
  /** The participant this device speaks for: a chain that removes it is
   *  refused. */
  participant: string
  /** The cumulative removed set this device already knows. Read once per
   *  call. */
  removed?: Iterable<string>
  /** The highest epoch this device has seen a valid rekey for. A grant
   *  that stops short of it is refused, so a member removed at that epoch
   *  cannot hold the requester one epoch back on a key it still has. */
  expected?: number
  now: number
  maxAgeSeconds?: number
}

/** A member grant, verified. */
export interface MemberEpochGrant {
  epoch: RoomEpoch
  /** Cumulative: `opts.removed` plus every removal in the chain. */
  removed: string[]
  /** The epochs between the requester's and `epoch`, oldest first, each
   *  proven by the next rekey in the chain decrypting under it. Empty for a
   *  grant one epoch ahead. Kept, they let the requester read what was said
   *  in the epochs it skipped, and hand them on from its own member desk. */
  passed: RoomEpoch[]
  /** The newest member list in the chain, when any rekey in it had one. */
  members?: string[]
}

/**
 * Verify a member's answer to one of this device's member requests. Null
 * for anything that does not check out - see the module comment and
 * `docs/member-epoch-catch-up.md` "Verification rules" for each check.
 */
export function decodeMemberEpochGrant(event: Event, opts: DecodeMemberEpochGrantOptions): MemberEpochGrant | null {
  try {
    if (event.kind !== MEMBER_EPOCH_KINDS.GRANT) return null
    if (!verifyEventUncached(event)) return null
    if (Math.abs(opts.now - event.created_at) > (opts.maxAgeSeconds ?? MAX_AGE_SECONDS)) return null
    const roomId = requireHex32(opts.roomId, 'room id')
    if (event.tags.find((t) => t[0] === 'd')?.[1]?.toLowerCase() !== roomId) return null
    const device = getPublicKey(opts.deviceSk)
    const addressed = event.tags.find((t) => t[0] === 'p')?.[1]
    if (addressed === undefined || !hexEquals(addressed, device)) return null
    const body = JSON.parse(
      nip44.v2.decrypt(event.content, nip44.v2.utils.getConversationKey(opts.deviceSk, event.pubkey)),
    ) as Partial<MemberEpochGrantBody>
    if (body.v !== 1 || typeof body.request !== 'string' || !HEX64.test(body.request)) return null
    if (![...opts.requests].some((r) => hexEquals(r, body.request as string))) return null
    if (!Array.isArray(body.secrets) || !Array.isArray(body.rekeys)) return null
    const length = body.secrets.length
    if (length < 1 || length > MAX_MEMBER_EPOCH_CHAIN || body.rekeys.length !== length) return null
    const top = opts.current.epoch + length
    if (body.epoch !== top || top > MAX_EPOCH) return null
    if (opts.expected !== undefined && top < opts.expected) return null
    const participant = normaliseHex(opts.participant)
    const removed = new Set([...(opts.removed ?? [])].map(normaliseHex))
    let previous: EpochKeys = opts.current
    let secret: Uint8Array | undefined
    const passed: RoomEpoch[] = []
    let members: string[] | undefined
    for (let i = 0; i < length; i += 1) {
      const evidence = readRekeyEvidence(body.rekeys[i] as Event, { roomId, authority: opts.authority, previous })
      if (!evidence) return null
      if (evidence.closed) return null
      if (evidence.removed.includes(participant)) return null
      for (const p of evidence.removed) removed.add(p)
      if (evidence.members) members = evidence.members
      const raw = body.secrets[i]
      if (typeof raw !== 'string') return null
      secret = base64urlnopad.decode(raw)
      if (secret.length !== 32) return null
      // Every secret but the last is proven by the next rekey decrypting
      // under it, on the next turn of this loop. The last has no next rekey:
      // the authority's commitment is the only thing that can vouch for it.
      if (i === length - 1) {
        if (evidence.commit === undefined) return null
        if (!constantTimeEquals(evidence.commit, epochCommitment(roomId, evidence.epoch, secret))) return null
      }
      previous = deriveEpoch({ epoch: evidence.epoch, secret })
      if (i < length - 1) passed.push({ epoch: evidence.epoch, secret })
    }
    return { epoch: { epoch: top, secret: secret! }, removed: [...removed].sort(), passed, ...(members ? { members } : {}) }
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// The member desk
// ---------------------------------------------------------------------------

export interface HostMemberEpochDeskOptions {
  transport: RelayTransport
  roomId: string
  authority: string
  /** This member's device key: the desk ignores requests from it. Grants
   *  are signed by a one-time key each (see `encodeMemberEpochGrant`). */
  deviceSk: Uint8Array
  /** The epoch-0 room key: opens requests and checks admission proofs. */
  roomKey: Uint8Array
  /** Where this device is now, or undefined while it is not in step (behind,
   *  removed, leaving). Asked on every request. */
  current: () => RoomEpoch | undefined
  /** The secret of an earlier epoch this device still holds, for a
   *  requester more than one epoch behind. Optional: without it this desk
   *  serves only requesters exactly one epoch behind. */
  secretAt?: (epoch: number) => Uint8Array | undefined
  /** The authority's rekey event into `epoch`, as this device stored it. */
  rekeyAt: (epoch: number) => Event | undefined
  /** The cumulative removed set, as the authority's rekeys told this device. */
  removed: () => ReadonlySet<string>
  /** True once the room has been closed. */
  closed?: () => boolean
  /**
   * Whether the room knows this participant: on the authority's latest
   * member list, in the room's current roster, or let in from this device.
   * Consulted only once somebody has been removed; then nobody else is
   * answered (#207). Without it, after a removal, nobody is known.
   */
  known?: (participant: string) => boolean
  /** Somebody the room does not know asked, after a removal. Called once
   *  per request; nothing is published. Letting them in is making `known`
   *  say yes, and their next ask is answered. */
  onUnknown?: (request: MemberEpochRequest) => void
  policy?: RoomPolicy
  now?: () => number
  /** Upper bound of the random wait before answering, so several members do
   *  not all answer at once. 0 answers at once. Default 1500. */
  jitterMs?: number
  /** For tests: a source of numbers in [0, 1). Default `Math.random`. */
  random?: () => number
  /** The largest serialised grant this desk will publish. Default 60000:
   *  under the 64 KiB many relays enforce. A longer chain is left to the
   *  authority. */
  maxGrantBytes?: number
  onGranted?: (request: MemberEpochRequest) => void
  /** Called when this desk declines a removed participant or a closed room.
   *  Nothing is published either way: a member's refusal is not something a
   *  requester could believe, so it is not sent. */
  onRefused?: (request: MemberEpochRequest, why: EpochRefusal) => void
  expiresAt?: number
}

/**
 * Answer member epoch requests for as long as the handle is open: what any
 * member at the current epoch runs beside its session. It answers only an
 * admitted, credentialled device that is not removed, in a room that is not
 * closed, from a participant the room knows once anybody has been removed
 * (see `hostRoomEpoch` for why), and only when it can hand over the whole
 * chain from the requester's epoch to its own with the authority's rekeys
 * to prove it.
 *
 * Anti-amplification: each answer waits a random `[0, jitterMs)`, and is
 * dropped if another member's grant to the same device appears meanwhile.
 * It is dropped at most once per requesting device: the requester asks again
 * with a fresh request if what it got did not verify, and the second time
 * every desk answers, so a stranger posting junk grants costs one round.
 */
export function hostMemberEpochDesk(opts: HostMemberEpochDeskOptions): { close(): void } {
  if (opts.deviceSk.length !== 32) throw new Error('device secret key must be 32 bytes')
  if (opts.roomKey.length !== 32) throw new Error('room key must be 32 bytes')
  const roomId = requireHex32(opts.roomId, 'room id')
  const authority = requireHex32(opts.authority, 'authority pubkey')
  const self = getPublicKey(opts.deviceSk)
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000))
  const random = opts.random ?? Math.random
  const jitterMs = Math.max(0, opts.jitterMs ?? DEFAULT_JITTER_MS)
  const answered = new Set<string>()
  /** Requesting devices another member's grant was seen for, since their
   *  latest request reached this desk. */
  const grantSeen = new Set<string>()
  /** Requesting devices this desk has already stood down for once. */
  const stoodDown = new Set<string>()
  /** Requests from a participant the room does not know: reported once,
   *  and looked at again when the requester asks again. */
  const unknown = new Set<string>()
  /** Ids of the grants this desk published: each is signed by a one-time
   *  key, so its own grants are told apart by id, not by signer. */
  const mine = new Set<string>()
  const timers = new Set<ReturnType<typeof setTimeout>>()
  let closed = false

  const bound = (set: Set<string>): void => {
    if (set.size > 256) set.delete(set.values().next().value!)
  }

  const chainFor = (have: number, current: RoomEpoch): { epochs: RoomEpoch[]; rekeys: Event[] } | null => {
    if (current.epoch - have > MAX_MEMBER_EPOCH_CHAIN) return null
    const epochs: RoomEpoch[] = []
    const rekeys: Event[] = []
    for (let n = have + 1; n <= current.epoch; n += 1) {
      const secret = n === current.epoch ? current.secret : opts.secretAt?.(n)
      const rekey = opts.rekeyAt(n)
      if (!secret || secret.length !== 32 || !rekey) return null
      if (peekRekeyEvent(rekey, { roomId, authority }) !== n) return null
      epochs.push({ epoch: n, secret })
      rekeys.push(rekey)
    }
    // When this device can read the last rekey itself, it checks the
    // commitment is there: a legacy epoch is the authority's to hand on, and
    // a grant the requester will refuse is noise. One it cannot read (it
    // joined at this epoch) it sends, and the requester decides.
    const before = current.epoch - 1
    const beforeSecret = before === 0 ? undefined : opts.secretAt?.(before)
    const beforeKey = before === 0 ? opts.roomKey : beforeSecret?.length === 32 ? deriveEpoch({ epoch: before, secret: beforeSecret }).key : undefined
    if (beforeKey) {
      const evidence = readRekeyEvidence(rekeys[rekeys.length - 1]!, {
        roomId,
        authority,
        previous: { epoch: before, id: '', key: beforeKey },
      })
      if (!evidence || evidence.commit === undefined) return null
    }
    return { epochs, rekeys }
  }

  const admissible = (request: MemberEpochRequest): boolean => {
    const removed = opts.removed()
    if ([...removed].some((p) => hexEquals(p, request.participant))) return false
    return removed.size === 0 || opts.known?.(request.participant) === true
  }

  const answer = (request: MemberEpochRequest): void => {
    if (closed) return
    if (grantSeen.has(request.device) && !stoodDown.has(request.device)) {
      stoodDown.add(request.device)
      bound(stoodDown)
      return
    }
    stoodDown.delete(request.device)
    // Asked again, now that the wait is over: the room may have moved.
    if (opts.closed?.()) return
    if (!admissible(request)) return
    const current = opts.current()
    if (!current || request.have >= current.epoch) return
    const chain = chainFor(request.have, current)
    if (!chain) return
    let grant: Event
    try {
      grant = encodeMemberEpochGrant({
        roomId,
        device: request.device,
        request: request.request,
        epochs: chain.epochs,
        rekeys: chain.rekeys,
        now: now(),
        expiresAt: opts.expiresAt,
      })
    } catch {
      return
    }
    if (JSON.stringify(grant).length > (opts.maxGrantBytes ?? DEFAULT_MAX_GRANT_BYTES)) return
    mine.add(grant.id)
    bound(mine)
    opts.transport.publish(grant).catch(() => {})
    opts.onGranted?.(request)
  }

  const unsubGrants = opts.transport.subscribe([{ kinds: [MEMBER_EPOCH_KINDS.GRANT], '#d': [roomId] }], (event) => {
    if (closed || mine.has(event.id)) return
    const to = event.tags.find((t) => t[0] === 'p')?.[1]
    if (to === undefined || !HEX64.test(to)) return
    grantSeen.add(normaliseHex(to))
    bound(grantSeen)
  })

  const unsubRequests = opts.transport.subscribe([{ kinds: [MEMBER_EPOCH_KINDS.REQUEST], '#d': [roomId] }], (event) => {
    if (closed || hexEquals(event.pubkey, self)) return
    const request = decodeMemberEpochRequest(event, { roomId, authority, roomKey: opts.roomKey, now: now(), policy: opts.policy })
    if (!request || answered.has(request.request)) return
    if (opts.closed?.()) {
      answered.add(request.request)
      bound(answered)
      opts.onRefused?.(request, 'closed')
      return
    }
    if ([...opts.removed()].some((p) => hexEquals(p, request.participant))) {
      answered.add(request.request)
      bound(answered)
      opts.onRefused?.(request, 'removed')
      return
    }
    if (!admissible(request)) {
      if (unknown.has(request.request)) return
      unknown.add(request.request)
      bound(unknown)
      opts.onUnknown?.(request)
      opts.onRefused?.(request, 'unknown')
      return
    }
    unknown.delete(request.request)
    answered.add(request.request)
    bound(answered)
    const current = opts.current()
    if (!current || request.have >= current.epoch) return
    grantSeen.delete(request.device)
    const delay = jitterMs === 0 ? 0 : Math.floor(random() * jitterMs)
    if (delay === 0) {
      answer(request)
      return
    }
    const timer = setTimeout(() => {
      timers.delete(timer)
      answer(request)
    }, delay)
    ;(timer as unknown as { unref?: () => void }).unref?.()
    timers.add(timer)
  })

  return {
    close() {
      if (closed) return
      closed = true
      for (const timer of timers) clearTimeout(timer)
      timers.clear()
      unsubRequests()
      unsubGrants()
    },
  }
}

// ---------------------------------------------------------------------------
// The requester
// ---------------------------------------------------------------------------

export interface MemberEpochRequestOptions {
  transport: RelayTransport
  roomId: string
  authority: string
  deviceSk: Uint8Array
  /** The epoch-0 room key. */
  roomKey: Uint8Array
  credential: DeviceCredential
  proof?: KindredProof
  /** Where this device is now. Asked each time a request goes out. */
  current: EpochKeys | (() => EpochKeys)
  /** The cumulative removed set this device already knows. A function is
   *  asked on every grant; anything else is read once, when the source is
   *  made, so a generator or other one-shot iterable is not used up by the
   *  first grant and seen as empty by the next. */
  removed?: Iterable<string> | (() => Iterable<string>)
  /** The highest epoch a valid rekey has been seen for: see
   *  `DecodeMemberEpochGrantOptions.expected`. The source also watches the
   *  room's rekeys on `transport` itself and floors every grant at the
   *  newest authority-signed one it sees, so this is only for what the
   *  caller learnt elsewhere. */
  expected?: number | (() => number | undefined)
  now?: () => number
  /** How often a fresh request goes out. Default 4000 ms. */
  retryMs?: number
  expiresAt?: number
}

/** What `requestRoomEpoch({ members })` takes: a second source of answers
 *  that starts when the request does and stops when it settles. */
export interface MemberEpochSource {
  start(onGrant: (grant: MemberEpochGrant) => void): () => void
}

/**
 * The member side of a catch-up, for `requestRoomEpoch({ members })`. Each
 * round publishes a fresh request (a new id, so a desk that stood down once
 * answers it), and the first grant that verifies is handed to `onGrant`.
 *
 * It subscribes to the room's rekeys (kind 1462) before it asks, and refuses
 * any grant that stops short of the newest one the authority signed: rule 3
 * of `docs/member-epoch-catch-up.md`, enforced here rather than left to the
 * caller, because a member removed at epoch E still holds E-1 and every
 * rekey up to it, and would otherwise hold the requester on a key it shares.
 */
export function memberEpochSource(opts: MemberEpochRequestOptions): MemberEpochSource {
  const roomId = requireHex32(opts.roomId, 'room id')
  const authority = requireHex32(opts.authority, 'authority pubkey')
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000))
  const device = getPublicKey(opts.deviceSk)
  const current = (): EpochKeys => (typeof opts.current === 'function' ? opts.current() : opts.current)
  const expected = (): number | undefined => (typeof opts.expected === 'function' ? opts.expected() : opts.expected)
  const knownRemoved: readonly string[] | undefined = typeof opts.removed === 'function' || opts.removed === undefined ? undefined : [...opts.removed]
  const removedNow = (): Iterable<string> | undefined => (typeof opts.removed === 'function' ? opts.removed() : knownRemoved)
  const verdict = verifyDeviceCredential(opts.credential, { roomId, now: now() })
  if (!verdict.ok) throw new Error(`device credential refused: ${verdict.reason}`)
  const participant = verdict.participant
  return {
    start(onGrant) {
      const requests = new Set<string>()
      let stopped = false
      let begun = false
      /** Set once everything below is wired up; EOSE can arrive before. */
      let ready = false
      let replayed = false
      let retry: ReturnType<typeof setInterval> | undefined
      let replayWait: ReturnType<typeof setTimeout> | undefined
      const stop = (): void => {
        if (stopped) return
        stopped = true
        if (retry !== undefined) clearInterval(retry)
        if (replayWait !== undefined) clearTimeout(replayWait)
        unsub()
        unsubRekeys()
      }
      // The floor: the newest epoch the authority has signed a rekey into, as
      // the relays replay it. `peekRekeyEvent` checks the signer, the room and
      // the signature, so nobody else can raise it.
      let seen = 0
      // The first request waits for the relays to finish replaying them
      // (EOSE), or for REKEY_REPLAY_WAIT_MS, so that a member answering
      // faster than the replay cannot slip a stale chain in under the floor.
      const unsubRekeys = opts.transport.subscribe(
        [{ kinds: [KINDS.ROOM_REKEY], '#d': [roomId] }],
        (event) => {
          const epoch = peekRekeyEvent(event, { roomId, authority })
          if (epoch !== null && epoch > seen) seen = epoch
        },
        () => {
          replayed = true
          if (ready) begin()
        },
      )
      const floor = (): number | undefined => {
        const given = expected()
        const top = Math.max(seen, given ?? 0)
        return top > 0 ? top : undefined
      }
      const unsub = opts.transport.subscribe([{ kinds: [MEMBER_EPOCH_KINDS.GRANT], '#d': [roomId], '#p': [device] }], (event) => {
        if (stopped) return
        const grant = decodeMemberEpochGrant(event, {
          roomId,
          authority,
          deviceSk: opts.deviceSk,
          requests,
          current: current(),
          participant,
          removed: removedNow(),
          expected: floor(),
          now: now(),
        })
        if (!grant) return
        stop()
        onGrant(grant)
      })
      const ask = (): void => {
        if (stopped) return
        let request: Event
        try {
          request = encodeMemberEpochRequest({
            roomId,
            authority,
            deviceSk: opts.deviceSk,
            roomKey: opts.roomKey,
            credential: opts.credential,
            proof: opts.proof,
            have: current().epoch,
            now: now(),
            expiresAt: opts.expiresAt,
          })
        } catch {
          return
        }
        requests.add(request.id)
        if (requests.size > 16) requests.delete(requests.values().next().value!)
        opts.transport.publish(request).catch(() => {})
      }
      function begin(): void {
        if (begun || stopped) return
        begun = true
        if (replayWait !== undefined) clearTimeout(replayWait)
        retry = setInterval(ask, opts.retryMs ?? DEFAULT_RETRY_MS)
        ;(retry as unknown as { unref?: () => void }).unref?.()
        ask()
      }
      ready = true
      if (replayed) begin()
      else {
        replayWait = setTimeout(begin, REKEY_REPLAY_WAIT_MS)
        ;(replayWait as unknown as { unref?: () => void }).unref?.()
      }
      return stop
    },
  }
}

/** Ask the room's current members alone (no authority) for the epochs this
 *  device missed. Rejects with a plain error when no verifiable answer comes
 *  inside the timeout. Most callers want `requestRoomEpoch({ members })`. */
export function requestMemberEpoch(opts: MemberEpochRequestOptions & { timeoutMs?: number }): Promise<MemberEpochGrant> {
  const source = memberEpochSource(opts)
  return new Promise((resolve, reject) => {
    let settled = false
    let stop = (): void => {}
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      stop()
      reject(new Error('no current member answered with an epoch that checks out'))
    }, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS)
    ;(timer as unknown as { unref?: () => void }).unref?.()
    stop = source.start((grant) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(grant)
    })
    if (settled) stop()
  })
}

/** Every wire-format literal this module owns, frozen for `src/labels.test.ts`. */
export const MEMBER_EPOCH_LABELS = [
  "kithmoot/v1/member-epoch-request-key",
] as const
