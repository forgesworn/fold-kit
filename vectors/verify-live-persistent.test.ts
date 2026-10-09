import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { nip44 } from 'nostr-tools'
import { withStubbedRandomness } from './lib/determinism.mjs'
import { encodeLivePersistentDescriptor, decodeLivePersistentDescriptor,
  encodeLivePersistentRequest, decodeLivePersistentRequest,
  encodeLivePersistentAnswer, decodeLivePersistentAnswer } from '../src/live-persistent-admission.js'
import { encodePersistentInvitation } from '../src/persistent-invitation.js'

const wire = (event: unknown) => JSON.parse(JSON.stringify(event))
const doc = JSON.parse(readFileSync(new URL('./live-persistent-vectors.json', import.meta.url), 'utf8'))
const vectors = doc.groups.livePersistentAdmission

describe('live persistent admission wire fixtures', () => {
  for (const v of vectors) it(v.name, () => {
    const i = v.input
    const invitation = { bearer: hexToBytes(i.bearerHex), inviter: i.inviter, persistent: true as const }
    const ctx = { invitation, roomId: i.roomId, now: i.now }
    if (v.operation === 'descriptor') {
      const got = decodeLivePersistentDescriptor(i.encoded, invitation)
      expect(got !== null).toBe(v.output.accepted)
      if (got) {
        expect(got.roomId).toBe(v.output.result.roomId)
        expect(encodeLivePersistentDescriptor(ctx)).toBe(i.encoded)
      }
    } else if (v.operation === 'request') {
      const got = decodeLivePersistentRequest(i.event, ctx)
      expect(got !== null).toBe(v.output.accepted)
      if (got) {
        expect(got).toEqual(v.output.result)
        expect(wire(withStubbedRandomness(i.randomHex.map(hexToBytes), () => encodeLivePersistentRequest({
          ...ctx, now: i.event.created_at, requesterSk: hexToBytes(i.requesterSkHex),
        })))).toEqual(i.event)
      }
    } else {
      expect(v.operation).toBe('answer')
      const got = decodeLivePersistentAnswer(i.event, { ...ctx, request: i.request, requesterSk: hexToBytes(i.requesterSkHex) })
      expect(got !== null).toBe(v.output.accepted)
      if (got) {
        const { secret, ...admission } = got.admission
        expect({ ...admission, secretHex: bytesToHex(secret), epochHint: got.epochHint,
          expiresAt: got.expiresAt, requestId: got.requestId }).toEqual(v.output.result)
        expect(wire(withStubbedRandomness(i.randomHex.map(hexToBytes), () => encodeLivePersistentAnswer({
          ...ctx, now: i.event.created_at, request: i.request, invitationEvent: i.invitationEvent,
          inviterSk: hexToBytes(i.inviterSkHex), epoch: i.epoch,
        })))).toEqual(i.event)
      }
    }
  })

  it('pins independent request derivation/plaintexts and unchanged persistent invitation bytes', () => {
    const r = vectors.find((v: { name: string }) => v.name === 'request').input
    const a = vectors.find((v: { name: string }) => v.name === 'answer').input
    const key = hkdf(sha256, hexToBytes(r.bearerHex), undefined, 'kithmoot/v1/persistent-live/request-key', 32)
    expect(bytesToHex(key)).toBe(doc.derivations.requestKeyHex)
    expect(nip44.v2.decrypt(r.event.content, key)).toBe(doc.derivations.requestPlaintext)
    expect(nip44.v2.decrypt(a.event.content, nip44.v2.utils.getConversationKey(hexToBytes(a.requesterSkHex), a.inviter)))
      .toBe(doc.derivations.answerPlaintext)
    expect(wire(withStubbedRandomness(doc.derivations.welcomeRandomHex.map(hexToBytes), () => encodePersistentInvitation({
      invitation: { bearer: hexToBytes(r.bearerHex), inviter: r.inviter, persistent: true },
      inviterSk: hexToBytes(doc.derivations.inviterSkHex), roomSecret: hexToBytes(doc.derivations.secretHex),
      now: a.invitationEvent.created_at, endsAt: a.event.created_at + 3599, destruct: true, relays: ['wss://relay.example/'],
    })))).toEqual(a.invitationEvent)
  })
})
