import { nip44 } from 'nostr-tools'
import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure'
import { hexEquals, normaliseHex } from './hex.js'
import { KINDS } from './kinds.js'
import { deriveInvitationId, verifyInvitationDelegation } from './invitation.js'
import type { DecodeInvitationGrantOptions, InvitationDelegation, RoomInvitation } from './invitation.js'
import { verifyEventUncached } from './verify.js'

export interface EncodeInvitationDeclineOptions {
  invitation: RoomInvitation
  inviterSk: Uint8Array
  requester: string
  request: string
  now: number
  /** Root-to-responder chain; empty only for the pinned root inviter. */
  delegation?: InvitationDelegation[]
}

export interface InvitationDecline {
  request: string
  responder: string
}

export class InvitationDeclinedError extends Error {
  constructor() {
    super('Someone in the room declined your request to join.')
    this.name = 'InvitationDeclinedError'
  }
}

/** A private refusal, carrying no room secret or new responder delegation.
 * Version 3 distinguishes it from version-2 grants on the same reply kind.
 * Older readers ignore it and continue their existing bounded wait. */
export function encodeInvitationDecline(opts: EncodeInvitationDeclineOptions): Event {
  if (opts.inviterSk.length !== 32) throw new Error('inviter secret key must be 32 bytes')
  if (!Number.isSafeInteger(opts.now) || opts.now < 0) throw new Error('invalid invitation decline time')
  if (!/^[0-9a-f]{64}$/i.test(opts.requester) || !/^[0-9a-f]{64}$/i.test(opts.request)) {
    throw new Error('request and requester must be 32-byte hex')
  }
  const responder = getPublicKey(opts.inviterSk)
  const delegation = opts.delegation ?? []
  const authority = verifyInvitationDelegation(opts.invitation, delegation, opts.now)
  if (authority === null || !hexEquals(authority, responder)) {
    throw new Error('responder is not delegated for invitation')
  }
  const requester = normaliseHex(opts.requester)
  return finalizeEvent({
    kind: KINDS.INVITATION_GRANT,
    created_at: opts.now,
    tags: [['d', deriveInvitationId(opts.invitation)], ['p', requester]],
    content: nip44.v2.encrypt(JSON.stringify({
      v: 3, decision: 'declined', request: normaliseHex(opts.request), delegation,
    }), nip44.v2.utils.getConversationKey(opts.inviterSk, requester)),
  }, opts.inviterSk)
}

/** Only a fresh, request-bound refusal from the pinned root or a currently
 * delegated responder can stop this guest's wait. A bearer holder has no
 * authority to refuse someone else. No room capability is returned. */
export function decodeInvitationDecline(event: Event, opts: DecodeInvitationGrantOptions): InvitationDecline | null {
  try {
    const age = opts.maxAgeSeconds ?? 90
    if (!Number.isSafeInteger(opts.now) || opts.now < 0 || !Number.isSafeInteger(age) || age < 0) return null
    if (event.kind !== KINDS.INVITATION_GRANT || !verifyEventUncached(event)) return null
    if (!Number.isSafeInteger(event.created_at) || event.created_at < 0 || Math.abs(opts.now - event.created_at) > age) return null
    const rendezvous = event.tags.filter(t => t[0] === 'd')
    const addressed = event.tags.filter(t => t[0] === 'p')
    if (rendezvous.length !== 1 || rendezvous[0]?.[1] !== deriveInvitationId(opts.invitation)) return null
    const requester = getPublicKey(opts.requesterSk)
    if (addressed.length !== 1 || !hexEquals(addressed[0]?.[1] ?? '', requester)) return null
    const body = JSON.parse(nip44.v2.decrypt(event.content,
      nip44.v2.utils.getConversationKey(opts.requesterSk, event.pubkey)))
    if (!body || body.v !== 3 || body.decision !== 'declined') return null
    if (typeof body.request !== 'string' || !/^[0-9a-f]{64}$/i.test(body.request) || !hexEquals(body.request, opts.request)) return null
    if ('secret' in body || !Array.isArray(body.delegation)) return null
    const authority = verifyInvitationDelegation(opts.invitation, body.delegation, opts.now)
    if (authority === null || !hexEquals(authority, event.pubkey)) return null
    return { request: normaliseHex(body.request), responder: normaliseHex(event.pubkey) }
  } catch {
    return null
  }
}
