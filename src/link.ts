import { base64urlnopad } from '@scure/base'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { parseRoomPolicy } from './room.js'
import { roomInvitation } from './invitation.js'
import { sanitiseDisplayName } from './display-name.js'
import type { RoomInvitation } from './invitation.js'
import type { RoomPolicy } from './types.js'
import { assertNetworkHintBounds, safeIceUrls, safeRelayUrls } from './network-hints.js'

export { safeIceUrls, safeRelayUrls } from './network-hints.js'

/** A normal room link is small enough for a QR code. This generous ceiling
 * stops a fragment from becoming an unbounded base64/JSON allocation. */
export const MAX_ROOM_LINK_FRAGMENT_LENGTH = 16_384

/**
 * Everything a room link carries, whichever version it is.
 *
 * The app has always written its own envelope around the library's join
 * payload - relay hints, ICE hints, a pairing code - and read it back with
 * a hand of helpers in the page. An agent joining from a Node process needs
 * to read exactly the same link a person was sent, so the envelope is a
 * library concern from here on: one parser, shared by the page and by
 * anything else that is handed a link.
 *
 * Exactly one of `invitation` (v2 live rendezvous or v3 stored group) and
 * `secret` (legacy version 1, the room traffic secret itself) is present.
 */
export interface RoomLink {
  /** V2 meeting invitation or v3 persistent group invitation. */
  invitation?: RoomInvitation
  /** Version 1: the room traffic secret, in the link. Legacy. */
  secret?: Uint8Array
  /** Relay hints. Empty means the reader's defaults. */
  relays: string[]
  /** STUN/TURN hints. Empty means the reader's defaults. */
  iceUrls: string[]
  /** The room's admission rule, when it has one. */
  policy?: RoomPolicy
  /** A one-off pairing code, on a link that adds a device. Never a key. */
  pairingCode?: Uint8Array
  /**
   * What the room is called, when whoever made the link gave it a name.
   *
   * A label for people, on the same terms as a display name: self-asserted,
   * bounded by `sanitiseDisplayName`, and never load-bearing. It rides in
   * the link because the link is the one thing every member of a room was
   * handed, so a room a person is in on three devices is called the same
   * thing on all of them. Absent when nobody named it.
   */
  name?: string
}

/** The fragment payload as written. Field names are short because the
 *  whole link has to fit in a QR code. */
interface RoomLinkPayload {
  v?: 2 | 3
  s?: string
  j?: string
  h?: string
  r?: unknown
  i?: unknown
  a?: unknown
  c?: string
  n?: unknown
}

/**
 * Read a room link. Throws on a link that does not parse, and on one that
 * carries an admission rule it cannot read - a dropped rule is an open
 * room, and failing open is the mistake carrying the rule was meant to
 * prevent.
 */
export function parseRoomLink(url: string): RoomLink {
  const hash = new URL(url).hash.slice(1)
  if (!hash) throw new Error('join URL has no fragment')
  if (hash.length > MAX_ROOM_LINK_FRAGMENT_LENGTH) throw new Error('join URL fragment is too large')
  let payload: RoomLinkPayload
  try {
    payload = JSON.parse(new TextDecoder().decode(base64urlnopad.decode(hash))) as RoomLinkPayload
  } catch {
    throw new Error('join URL fragment is not valid')
  }
  if (typeof payload !== 'object' || payload === null) throw new Error('join URL fragment is not valid')
  if (payload.v !== undefined && payload.v !== 2 && payload.v !== 3) throw new Error('join URL uses an unsupported version')
  assertNetworkHintBounds(payload.r, payload.i)

  const link: RoomLink = {
    relays: safeRelayUrls(payload.r),
    iceUrls: safeIceUrls(payload.i),
  }
  const policy = parseRoomPolicy(payload.a)
  if (policy) link.policy = policy
  // Sanitised on the way in like a display name, because a link is text a
  // stranger wrote and a room name lands in the same places a name does.
  const name = sanitiseDisplayName(typeof payload.n === 'string' ? payload.n : undefined)
  if (name !== undefined) link.name = name
  if (typeof payload.c === 'string') {
    try {
      link.pairingCode = hexToBytes(payload.c)
    } catch {
      throw new Error('join URL carries a malformed pairing code')
    }
  }

  if (payload.v === 2 || payload.v === 3) {
    if (typeof payload.j !== 'string' || typeof payload.h !== 'string') {
      throw new Error('join URL carries a malformed invitation')
    }
    let bearer: Uint8Array
    try {
      bearer = base64urlnopad.decode(payload.j)
    } catch {
      throw new Error('join URL carries a malformed invitation')
    }
    link.invitation = roomInvitation(bearer, payload.h, payload.v === 3)
    return link
  }

  if (typeof payload.s !== 'string') throw new Error('join URL carries neither an invitation nor a secret')
  let secret: Uint8Array
  try {
    secret = base64urlnopad.decode(payload.s)
  } catch {
    throw new Error('join URL carries a malformed secret')
  }
  if (secret.length !== 32) throw new Error('join URL carries a malformed secret')
  link.secret = secret
  return link
}

/** Write a room link, in the same envelope the app writes. */
export function encodeRoomLink(base: string, link: RoomLink): string {
  assertNetworkHintBounds(link.relays, link.iceUrls)
  const relays = safeRelayUrls(link.relays)
  const iceUrls = safeIceUrls(link.iceUrls)
  const payload: RoomLinkPayload & { r: string[]; i: string[] } = link.invitation
    ? { v: link.invitation.persistent ? 3 : 2, j: base64urlnopad.encode(link.invitation.bearer), h: link.invitation.inviter, r: relays, i: iceUrls }
    : { s: base64urlnopad.encode(link.secret ?? invalid()), r: relays, i: iceUrls }
  if (link.policy) payload.a = link.policy
  if (link.pairingCode) payload.c = bytesToHex(link.pairingCode)
  // Written only when there is one, so a link to an unnamed room is
  // byte-identical to one written before rooms had names.
  const name = sanitiseDisplayName(link.name)
  if (name !== undefined) payload.n = name
  const fragment = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(payload)))
  if (fragment.length > MAX_ROOM_LINK_FRAGMENT_LENGTH) throw new Error('room link fragment is too large')
  return `${base}#${fragment}`
}

function invalid(): never {
  throw new Error('a room link needs an invitation or a secret')
}
