#!/usr/bin/env node
import { writeFileSync } from 'node:fs'
import { bytesToHex } from '@noble/hashes/utils'
import { getPublicKey } from 'nostr-tools/pure'
import {
  deriveInvitationId, deriveRoom, encodeInvitationGrant, encodeInvitationRequest, encodeRoomLink,
} from '../dist/index.js'
import { deriveSecretKey, seed32, withStubbedRandomness } from '../vectors/lib/determinism.mjs'

// Public synthetic credentials for checking the same wire format in each client.
const base = 'https://example.test/j/'
const now = 1_800_000_000
const roomSecret = seed32('owner-approved/original')
const approvedEpoch = { epoch: 1, secret: seed32('owner-approved/new'), rotatedAt: now - 15 }
const inviterSk = deriveSecretKey('owner-approved/owner')
const requesterSk = deriveSecretKey('owner-approved/member')
const invitation = {
  bearer: seed32('owner-approved/bearer'),
  inviter: getPublicKey(inviterSk),
  ownerApprovedRoom: deriveRoom(roomSecret).roomId,
}
const requestRandom = [seed32('owner-approved/request/nonce'), seed32('owner-approved/request/aux')]
const grantRandom = [seed32('owner-approved/grant/nonce'), seed32('owner-approved/grant/aux')]
const request = withStubbedRandomness(requestRandom, () => encodeInvitationRequest({ invitation, requesterSk, now }))
const grant = withStubbedRandomness(grantRandom, () => encodeInvitationGrant({
  invitation, inviterSk, requester: request.pubkey, request: request.id, roomSecret, now, approvedEpoch,
}))
const vector = {
  syntheticOnly: true, base, now,
  roomId: invitation.ownerApprovedRoom,
  invitationId: deriveInvitationId(invitation),
  link: encodeRoomLink(base, { invitation, relays: ['wss://relay.example'], iceUrls: [] }),
  ownerKeyHex: bytesToHex(inviterSk),
  requesterKeyHex: bytesToHex(requesterSk),
  roomSecretHex: bytesToHex(roomSecret),
  epoch: { epoch: approvedEpoch.epoch, secretHex: bytesToHex(approvedEpoch.secret), rotatedAt: approvedEpoch.rotatedAt },
  requestRandom: requestRandom.map(bytesToHex),
  grantRandom: grantRandom.map(bytesToHex),
  request, grant,
}
writeFileSync(new URL('../vectors/owner-approved-invitation-vectors.json', import.meta.url), JSON.stringify(vector, null, 2) + '\n')
