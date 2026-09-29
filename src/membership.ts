import { base64urlnopad } from '@scure/base'
import { getPublicKey } from 'nostr-tools/pure'
import { MAX_EPOCH, type RoomEpoch } from './epoch.js'
import { deriveRoom } from './room.js'

/** A storage-independent capability record; parsing it does not establish standing. */
export interface CircleMembership {
  v: 1
  roomId: string
  authority: string
  current: { epoch: number; secret: string }
  invitation?: { v: 2 | 3 | 4; bearer: string; inviter: string }
  authorityKey?: string
}

const HEX = /^[0-9a-f]{64}$/
function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
}
function bytes32(value: unknown): Uint8Array | null {
  if (typeof value !== 'string' || value.length !== 43) return null
  try {
    const bytes = base64urlnopad.decode(value)
    return bytes.length === 32 && base64urlnopad.encode(bytes) === value ? bytes : null
  } catch { return null }
}
function fields(value: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key))
}

/** Strict owned copy. Later-epoch root binding must come from verified admission/rekey. */
export function parseCircleMembership(value: unknown): CircleMembership | null {
  try {
    if (!object(value) || !fields(value, ['v', 'roomId', 'authority', 'current', 'invitation', 'authorityKey']) || value.v !== 1 ||
        typeof value.roomId !== 'string' || !HEX.test(value.roomId) || typeof value.authority !== 'string' || !HEX.test(value.authority)) return null
    const current = value.current
    if (!object(current) || !fields(current, ['epoch', 'secret']) || typeof current.epoch !== 'number' ||
        !Number.isSafeInteger(current.epoch) || current.epoch < 0 || current.epoch > MAX_EPOCH) return null
    const secret = bytes32(current.secret)
    if (!secret || (current.epoch === 0 && deriveRoom(secret).roomId !== value.roomId)) return null
    const result: CircleMembership = { v: 1, roomId: value.roomId, authority: value.authority,
      current: { epoch: current.epoch, secret: current.secret as string } }
    if (value.invitation !== undefined) {
      const invitation = value.invitation
      if (!object(invitation) || !fields(invitation, ['v', 'bearer', 'inviter']) ||
          ![2, 3, 4].includes(invitation.v as number) || !bytes32(invitation.bearer) || invitation.inviter !== value.authority) return null
      result.invitation = { v: invitation.v as 2 | 3 | 4, bearer: invitation.bearer as string, inviter: value.authority }
    }
    if (value.authorityKey !== undefined) {
      const key = bytes32(value.authorityKey)
      if (!key || getPublicKey(key) !== value.authority) return null
      result.authorityKey = value.authorityKey as string
    }
    return result
  } catch { return null }
}

export function circleMembershipEpoch(value: CircleMembership): RoomEpoch {
  const record = parseCircleMembership(value)
  if (!record) throw new TypeError('Invalid circle membership')
  return { epoch: record.current.epoch, secret: base64urlnopad.decode(record.current.secret) }
}

export function circleAuthorityKey(value: CircleMembership): Uint8Array | undefined {
  const record = parseCircleMembership(value)
  if (!record) throw new TypeError('Invalid circle membership')
  return record.authorityKey === undefined ? undefined : base64urlnopad.decode(record.authorityKey)
}
