import { readFileSync } from 'node:fs'
import { hexToBytes } from '@noble/hashes/utils'
import { getPublicKey } from 'nostr-tools/pure'
import { expect, it } from 'vitest'
import { withStubbedRandomness } from './lib/determinism.mjs'
import {
  decodeInvitationRequest, decodeOwnerApprovedRoomAdmissionGrant, deriveInvitationId,
  encodeInvitationGrant, encodeInvitationRequest,
} from '../src/invitation.js'
import { encodeRoomLink, parseRoomLink } from '../src/link.js'

const vector = JSON.parse(readFileSync(new URL('./owner-approved-invitation-vectors.json', import.meta.url), 'utf8'))

it('reproduces the owner-approved link, signed request and encrypted grant byte for byte', () => {
  const link = parseRoomLink(vector.link)
  const invitation = link.invitation!
  const inviterSk = hexToBytes(vector.ownerKeyHex)
  const requesterSk = hexToBytes(vector.requesterKeyHex)
  const roomSecret = hexToBytes(vector.roomSecretHex)
  const approvedEpoch = {
    epoch: vector.epoch.epoch, secret: hexToBytes(vector.epoch.secretHex), rotatedAt: vector.epoch.rotatedAt,
  }
  const now = vector.now
  expect(encodeRoomLink(vector.base, link)).toBe(vector.link)
  expect(invitation.inviter).toBe(getPublicKey(inviterSk))
  expect(invitation.ownerApprovedRoom).toBe(vector.roomId)
  expect(deriveInvitationId(invitation)).toBe(vector.invitationId)
  const request = withStubbedRandomness(vector.requestRandom.map(hexToBytes), () =>
    encodeInvitationRequest({ invitation, requesterSk, now }))
  expect(JSON.parse(JSON.stringify(request))).toEqual(vector.request)
  expect(decodeInvitationRequest(request, { invitation, now })).toEqual({ device: request.pubkey, request: request.id })
  const grant = withStubbedRandomness(vector.grantRandom.map(hexToBytes), () =>
    encodeInvitationGrant({ invitation, inviterSk, requester: request.pubkey, request: request.id, roomSecret, now, approvedEpoch }))
  expect(JSON.parse(JSON.stringify(grant))).toEqual(vector.grant)
  expect(decodeOwnerApprovedRoomAdmissionGrant(grant, { invitation, requesterSk, request: request.id, now })).toEqual({
    secret: roomSecret, epoch: approvedEpoch,
  })
})
