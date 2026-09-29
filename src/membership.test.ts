import { expect, it } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { getPublicKey } from 'nostr-tools/pure'
import { deriveRoom } from './room.js'
import { parseCircleMembership, circleMembershipEpoch, circleAuthorityKey, type CircleMembership } from './membership.js'

const secret = new Uint8Array(32).fill(7)
const key = new Uint8Array(32).fill(8)
const authority = getPublicKey(key)
const record: CircleMembership = { v: 1, roomId: deriveRoom(secret).roomId, authority,
  current: { epoch: 0, secret: base64urlnopad.encode(secret) }, authorityKey: base64urlnopad.encode(key),
  invitation: { v: 3, bearer: base64urlnopad.encode(new Uint8Array(32).fill(9)), inviter: authority } }

it('returns owned membership data and freshly decoded keys', () => {
  const parsed = parseCircleMembership(record)!
  expect(parsed).toEqual(record)
  parsed.current.epoch = 1
  parsed.invitation!.v = 4
  expect(record.current.epoch).toBe(0)
  expect(record.invitation!.v).toBe(3)
  expect(circleMembershipEpoch(record)).toEqual({ epoch: 0, secret })
  expect(circleAuthorityKey(record)).toEqual(key)
})

it('accepts current-only later-epoch membership without the original secret or keeper key', () => {
  const value = { v: 1, roomId: record.roomId, authority, current: { epoch: 4, secret: base64urlnopad.encode(new Uint8Array(32).fill(12)) } }
  expect(parseCircleMembership(value)).toEqual(value)
  expect(circleAuthorityKey(value as CircleMembership)).toBeUndefined()
})

it('refuses invalid scalars, mismatched root/authority, noncanonical encoding and unknown fields', () => {
  const cases = [null, [], {}, { ...record, v: 2 }, { ...record, roomId: '0'.repeat(64) },
    { ...record, authorityKey: base64urlnopad.encode(new Uint8Array(32)) },
    { ...record, authorityKey: base64urlnopad.encode(new Uint8Array(32).fill(10)) },
    { ...record, current: { ...record.current, secret: record.current.secret + '=' } },
    { ...record, current: { ...record.current, epoch: 1.5 } },
    { ...record, invitation: { ...record.invitation, inviter: '0'.repeat(64) } },
    { ...record, invitation: { ...record.invitation, bearer: 'short' } },
    { ...record, signerSecret: 'not allowed' }]
  for (const value of cases) expect(parseCircleMembership(value)).toBeNull()
  expect(() => circleMembershipEpoch({} as CircleMembership)).toThrow('Invalid circle membership')
})
