import { base64urlnopad } from '@scure/base'
import { sanitiseDisplayName } from './display-name.js'
import { MAX_ROOM_LINK_FRAGMENT_LENGTH } from './link.js'
import { assertNetworkHintBounds, isSafeRelayUrl, safeRelayUrls } from './network-hints.js'
import type { EpochInvitation } from './epoch-invitation.js'

function validInvitation(value: EpochInvitation): void {
  if (value.v !== 4 || !(value.bearer instanceof Uint8Array) || value.bearer.length !== 32 ||
      !/^[0-9a-f]{64}$/.test(value.inviter)) throw new Error('invalid epoch invitation')
}

export function encodeEpochInvitationLink(base: string, value: {
  invitation: EpochInvitation; relays: string[]; name?: string
}): string {
  validInvitation(value.invitation)
  assertNetworkHintBounds(value.relays, [])
  if (value.relays.some((relay) => !isSafeRelayUrl(relay))) throw new Error('invalid relay hint')
  const relays = safeRelayUrls(value.relays)
  if (relays.length !== value.relays.length) throw new Error('duplicate relay hint')
  const name = sanitiseDisplayName(value.name)
  const payload = { v: 4, j: base64urlnopad.encode(value.invitation.bearer), h: value.invitation.inviter,
    r: relays, ...(name === undefined ? {} : { n: name }) }
  const fragment = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(payload)))
  if (fragment.length > MAX_ROOM_LINK_FRAGMENT_LENGTH) throw new Error('epoch invitation link is too large')
  return `${base}#${fragment}`
}

export function parseEpochInvitationLink(url: string): {
  invitation: EpochInvitation; relays: string[]; name?: string
} {
  const hash = new URL(url).hash.slice(1)
  if (!hash || hash.length > MAX_ROOM_LINK_FRAGMENT_LENGTH) throw new Error('invalid epoch invitation link')
  let payload: unknown
  try {
    const bytes = base64urlnopad.decode(hash)
    if (base64urlnopad.encode(bytes) !== hash) throw new Error('noncanonical fragment')
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch { throw new Error('invalid epoch invitation link') }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('invalid epoch invitation link')
  const fields = payload as Record<string, unknown>
  if (fields.v !== 4 || Object.keys(fields).some((key) => !['v', 'j', 'h', 'r', 'n'].includes(key)) ||
      typeof fields.j !== 'string' || typeof fields.h !== 'string' || !Array.isArray(fields.r)) {
    throw new Error('invalid epoch invitation link')
  }
  let bearer: Uint8Array
  try { bearer = base64urlnopad.decode(fields.j) }
  catch { throw new Error('invalid epoch invitation bearer') }
  if (base64urlnopad.encode(bearer) !== fields.j) throw new Error('noncanonical epoch invitation bearer')
  const invitation: EpochInvitation = { v: 4, bearer, inviter: fields.h }
  validInvitation(invitation)
  assertNetworkHintBounds(fields.r, [])
  if (fields.r.some((relay) => typeof relay !== 'string' || !isSafeRelayUrl(relay))) throw new Error('invalid relay hint')
  const relays = safeRelayUrls(fields.r)
  if (relays.length !== fields.r.length) throw new Error('duplicate relay hint')
  const name = sanitiseDisplayName(fields.n)
  if (fields.n !== undefined && (typeof fields.n !== 'string' || name !== fields.n)) throw new Error('invalid epoch invitation name')
  return { invitation, relays, ...(name === undefined ? {} : { name }) }
}
