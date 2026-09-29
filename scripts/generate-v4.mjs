#!/usr/bin/env node
// Intentional v4-only known answer; v1/v2/v3 vector files remain frozen.
import { writeFileSync } from 'node:fs'
import { bytesToHex } from '@noble/hashes/utils'
import { getPublicKey } from 'nostr-tools/pure'
import {
  deriveRoom, encodeEpochInvitation, encodeEpochInvitationLink, decodeEpochInvitation,
  EPOCH_INVITATION_KEY_INFO,
} from '../dist/index.js'
import { seed32, deriveSecretKey, withStubbedRandomness } from '../vectors/lib/determinism.mjs'

const authoritySk = deriveSecretKey('v4/authority')
const roomId = deriveRoom(seed32('v4/root-secret')).roomId
const current = { epoch: 3, secret: seed32('v4/current-secret') }
const invitation = { v: 4, bearer: seed32('v4/bearer'), inviter: getPublicKey(authoritySk) }
const now = 1_900_000_000
const app = { title: 'Circle', nested: { count: 2 } }
const event = withStubbedRandomness([seed32('v4/nonce'), seed32('v4/signature-aux')], () =>
  encodeEpochInvitation({ invitation, authoritySk, roomId, current, app, now }))
const link = encodeEpochInvitationLink('https://example.test/join', { invitation, relays: ['wss://one.example'], name: 'Circle' })
const decoded = decodeEpochInvitation(event, invitation)
if (!decoded) throw new Error('v4 vector failed to decode')
const vector = { v: 4, info: EPOCH_INVITATION_KEY_INFO, roomId, currentEpoch: current.epoch,
  currentSecret: bytesToHex(current.secret), rootSecret: bytesToHex(seed32('v4/root-secret')),
  bearer: bytesToHex(invitation.bearer), authority: invitation.inviter, now, app, link, event }
writeFileSync(new URL('../vectors/v4-invitation.json', import.meta.url), `${JSON.stringify(vector, null, 2)}\n`)
