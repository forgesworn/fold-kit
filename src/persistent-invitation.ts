import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { base64urlnopad } from '@scure/base'
import { nip44 } from 'nostr-tools'
import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure'
import { decodeInvitationRetirementNotice, deriveInvitationId, retirementError, type RoomInvitation } from './invitation.js'
import { KINDS } from './kinds.js'
import { deriveRoom } from './room.js'
import { verifyEventUncached } from './verify.js'
import type { RelayTransport } from './transport.js'

/** Durable membership is distinct from temporary permission to admit others.
 * No inviter or delegated signing key is handed to a group member. */
export interface PersistentRoomAdmission {
  secret: Uint8Array
  persistent: true
  epoch: 0
}

function welcomeKey(invitation: RoomInvitation): Uint8Array {
  if (!invitation.persistent) throw new Error('a persistent group invitation is required')
  if (invitation.bearer.length !== 32) throw new Error('invitation bearer must be 32 bytes')
  return hkdf(sha256, invitation.bearer, undefined, 'kithmoot/v3/group-invitation-key', 32)
}

/** Publish once before sharing. The link plus this envelope is a durable
 * bearer capability: anybody holding both can learn epoch 0. Retirement
 * tells cooperative clients to stop admitting; it cannot erase copies. */
export function encodePersistentInvitation(opts: {
  invitation: RoomInvitation
  inviterSk: Uint8Array
  roomSecret: Uint8Array
  now: number
}): Event {
  if (getPublicKey(opts.inviterSk) !== opts.invitation.inviter) throw new Error('only the inviter can publish a group invitation')
  const room = deriveRoom(opts.roomSecret).roomId
  return finalizeEvent({
    kind: KINDS.GROUP_INVITATION,
    created_at: opts.now,
    tags: [['d', deriveInvitationId(opts.invitation)]],
    content: nip44.v2.encrypt(JSON.stringify({
      v: 3, room, secret: base64urlnopad.encode(opts.roomSecret),
    }), welcomeKey(opts.invitation)),
  }, opts.inviterSk)
}

export function decodePersistentInvitation(event: Event, invitation: RoomInvitation): PersistentRoomAdmission | null {
  try {
    if (event.kind !== KINDS.GROUP_INVITATION || event.pubkey !== invitation.inviter) return null
    if (!verifyEventUncached(event)) return null
    if (event.tags.filter(t => t[0] === 'd').length !== 1 ||
        event.tags.find(t => t[0] === 'd')?.[1] !== deriveInvitationId(invitation)) return null
    const body = JSON.parse(nip44.v2.decrypt(event.content, welcomeKey(invitation))) as Record<string, unknown>
    if (body.v !== 3 || typeof body.secret !== 'string') return null
    const secret = base64urlnopad.decode(body.secret)
    if (deriveRoom(secret).roomId !== body.room) return null
    return { secret, persistent: true, epoch: 0 }
  } catch { return null }
}

/** Fetch the signed envelope and retirement in ONE stored-event query.
 * Wait for EOSE even if the welcome arrives first: a tombstone replayed
 * later in the same result must win. A timeout never admits on partial
 * results. Relays remain an availability dependency, as they are for chat;
 * no member or keeper has to answer a live request. */
export function requestPersistentRoomAdmission(opts: {
  transport: RelayTransport
  invitation: RoomInvitation
  timeoutMs?: number
}): Promise<PersistentRoomAdmission> {
  if (!opts.invitation.persistent) return Promise.reject(new Error('a persistent group invitation is required'))
  return new Promise((resolve, reject) => {
    let settled = false
    let admission: PersistentRoomAdmission | undefined
    let unsub = () => {}
    const timer = setTimeout(() => finish(new Error('the group invitation could not be loaded from its relays')), opts.timeoutMs ?? 15_000)
    function finish(error?: Error): void {
      if (settled) return
      settled = true
      clearTimeout(timer)
      unsub()
      if (error) reject(error)
      else resolve(admission!)
    }
    try {
      unsub = opts.transport.subscribe([{
        kinds: [KINDS.GROUP_INVITATION, KINDS.INVITATION_RETIREMENT],
        authors: [opts.invitation.inviter], '#d': [deriveInvitationId(opts.invitation)],
      }], event => {
        if (settled) return
        const retired = decodeInvitationRetirementNotice(event, opts.invitation)
        if (retired) {
          finish(retirementError(retired))
          return
        }
        const decoded = decodePersistentInvitation(event, opts.invitation)
        if (!decoded) return
        if (admission && deriveRoom(admission.secret).roomId !== deriveRoom(decoded.secret).roomId) {
          finish(new Error('the group invitation names conflicting rooms'))
          return
        }
        admission = decoded
      }, () => {
        if (admission) finish()
        else finish(new Error('the group invitation is not available on its relays'))
      })
      if (settled) unsub()
    } catch (error) { finish(error instanceof Error ? error : new Error(String(error))) }
  })
}

/** Every wire-format literal this module owns (each one a kithmoot protocol string), frozen for
 *  `src/labels.test.ts`, which checks each module against its own exported
 *  list rather than scanning file text for matching comments. Pure data -
 *  adding this export changes no runtime behaviour. */
export const PERSISTENT_INVITATION_LABELS = [
  "kithmoot/v3/group-invitation-key",
] as const
