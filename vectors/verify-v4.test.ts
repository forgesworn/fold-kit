import { readFileSync } from 'node:fs'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { describe, expect, it } from 'vitest'
import { getPublicKey } from 'nostr-tools/pure'
import {
  deriveRoom, encodeEpochInvitation, decodeEpochInvitation, encodeEpochInvitationLink,
  EPOCH_INVITATION_KEY_INFO,
} from '../src/index.js'
import { seed32, deriveSecretKey, withStubbedRandomness } from './lib/determinism.mjs'

const vector = JSON.parse(readFileSync(new URL('./v4-invitation.json', import.meta.url), 'utf8'))

describe('v4 invitation known answer', () => {
  it('recomputes the signed current-epoch welcome and link from labelled inputs', () => {
    const authoritySk = deriveSecretKey('v4/authority')
    const invitation = { v: 4 as const, bearer: seed32('v4/bearer'), inviter: getPublicKey(authoritySk) }
    const rootSecret = seed32('v4/root-secret')
    const roomId = deriveRoom(rootSecret).roomId
    const current = { epoch: 3, secret: seed32('v4/current-secret') }
    const event = withStubbedRandomness([seed32('v4/nonce'), seed32('v4/signature-aux')], () =>
      encodeEpochInvitation({ invitation, authoritySk, roomId, current, app: vector.app, now: vector.now }))
    expect(EPOCH_INVITATION_KEY_INFO).toBe(vector.info)
    expect(roomId).toBe(vector.roomId)
    expect(bytesToHex(rootSecret)).toBe(vector.rootSecret)
    expect(bytesToHex(current.secret)).toBe(vector.currentSecret)
    expect(bytesToHex(invitation.bearer)).toBe(vector.bearer)
    expect(invitation.inviter).toBe(vector.authority)
    expect(JSON.parse(JSON.stringify(event))).toEqual(vector.event)
    expect(encodeEpochInvitationLink('https://example.test/join', { invitation,
      relays: ['wss://one.example'], name: 'Circle' })).toBe(vector.link)
    expect(decodeEpochInvitation(vector.event, { ...invitation, bearer: hexToBytes(vector.bearer) }))
      .toEqual({ roomId, authority: invitation.inviter, current, app: vector.app })
  })
})
