import { readFileSync } from 'node:fs'
import { expect, it } from 'vitest'
import { hexToBytes } from '@noble/hashes/utils'
import { getPublicKey, getEventHash, verifyEvent } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { roomInvitation, decodeInvitationGrant } from '../src/invitation.js'
import { encodeInvitationDecline, decodeInvitationDecline } from '../src/invitation-decline.js'
import { finalizeDeterministic, withStubbedRandomness } from './lib/determinism.mjs'

const { input, cases } = JSON.parse(readFileSync(new URL('./invitation-decline-vectors.json', import.meta.url), 'utf8'))
const inviterSk = hexToBytes(input.inviterSkHex), requesterSk = hexToBytes(input.requesterSkHex)
const invitation = roomInvitation(hexToBytes(input.bearerHex), getPublicKey(inviterSk))
const plain = ({ id, pubkey, created_at, kind, tags, content, sig }: any) => ({ id, pubkey, created_at, kind, tags, content, sig })
for (const row of cases) it(`verifies and exactly rebuilds ${row.name} refusal known answer`, () => {
  const opts = { invitation, requesterSk, request: input.request, now: input.now }
  expect(row.event.id).toBe(getEventHash(row.event))
  expect(verifyEvent(row.event)).toBe(true)
  expect(decodeInvitationDecline(row.event, opts)).toEqual(row.accepted ? { request: input.request, responder: invitation.inviter } : null)
  expect(decodeInvitationGrant(row.event, opts)).toBeNull()
  const signer = row.name === 'unauthorised' ? hexToBytes(input.outsiderSkHex) : inviterSk
  const key = nip44.v2.utils.getConversationKey(requesterSk, row.event.pubkey)
  const body = nip44.v2.decrypt(row.event.content, key)
  const rebuilt = finalizeDeterministic({ kind: row.event.kind, created_at: input.now, tags: row.event.tags,
    content: nip44.v2.encrypt(body, nip44.v2.utils.getConversationKey(signer, getPublicKey(requesterSk)), hexToBytes(row.nonceHex)),
  }, signer, hexToBytes(row.auxHex))
  expect(plain(rebuilt)).toEqual(plain(row.event))
  if (row.accepted) {
    const encoded = withStubbedRandomness([hexToBytes(row.nonceHex), hexToBytes(row.auxHex)], () =>
      encodeInvitationDecline({ invitation, inviterSk, requester: getPublicKey(requesterSk), request: input.request, now: input.now }))
    expect(plain(encoded)).toEqual(plain(row.event))
  }
})
