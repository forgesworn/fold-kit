import { readFileSync } from 'node:fs'
import { createHash, hkdfSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { nip44 } from 'nostr-tools'
import { getPublicKey } from 'nostr-tools/pure'
import {
  MLS_ADMISSION_LABELS, readMlsInvitationV4, mlsAdmissionProofTemplatesV4,
  decodeMlsAdmissionRequestV4, readMlsAdmissionRequestV4,
  decodeMlsAdmissionAnswerV4, readMlsAdmissionAnswerV4,
} from '../src/mls-admission.js'
const vector = JSON.parse(readFileSync(new URL('./mls-admission-v4.json', import.meta.url), 'utf8'))
const root = new Uint8Array(Buffer.from(vector.rootSecretHex, 'hex'))
const requestSk = new Uint8Array(Buffer.from(vector.requestSecretHex, 'hex'))
describe('independently composed frozen MLS admission v4 vectors', () => {
  it('pins the link, HKDF direction keys and canonical core digests', () => {
    expect(readMlsInvitationV4(vector.fragment).invitationId).toBe(vector.invitationId)
    const base = nip44.v2.utils.getConversationKey(requestSk, getPublicKey(root))
    expect(Buffer.from(base).toString('hex')).toBe(vector.baseKeyHex)
    for (const [label, expected] of [[MLS_ADMISSION_LABELS[1], vector.requestKeyHex], [MLS_ADMISSION_LABELS[2], vector.answerKeyHex]]) {
      expect(Buffer.from(hkdfSync('sha256', base, Buffer.from(vector.bearerHex, 'hex'), Buffer.from(label), 32)).toString('hex')).toBe(expected)
    }
    for (const [core, digest] of [[vector.requestCore, vector.requestDigest], [vector.allowCore, vector.allowDigest], [vector.denyCore, vector.denyDigest]]) {
      expect(createHash('sha256').update(core).digest('hex')).toBe(digest)
    }
  })
  it('decodes the independently signed/encrypted request, Allow and Deny', () => {
    const request = decodeMlsAdmissionRequestV4({ fragment: vector.fragment, event: vector.requestEvent, localSecretKey: requestSk, side: 'joiner', now: vector.now })
    const host = decodeMlsAdmissionRequestV4({ fragment: vector.fragment, event: vector.requestEvent, localSecretKey: root, side: 'root', now: vector.now })
    expect(readMlsAdmissionRequestV4(request).core).toBe(vector.requestCore)
    expect(readMlsAdmissionRequestV4(host).digest).toBe(vector.requestDigest)
    for (const [event, expectedCore, digest, decision] of [
      [vector.allowEvent, vector.allowCore, vector.allowDigest, 'allow'],
      [vector.denyEvent, vector.denyCore, vector.denyDigest, 'deny'],
    ]) {
      const answer = readMlsAdmissionAnswerV4(decodeMlsAdmissionAnswerV4({ fragment: vector.fragment, request, event, requestSecretKey: requestSk, now: vector.now }))
      expect(answer.core).toBe(expectedCore); expect(answer.digest).toBe(digest); expect(answer.decision).toBe(decision)
      expect(JSON.parse(event).content.length).toBe(vector.ciphertextCharacters)
    }
    const specs = mlsAdmissionProofTemplatesV4({ fragment: vector.fragment, core: vector.allowCore, now: vector.now, request: host })
    expect(specs.map(s => s.event.content)).toEqual([JSON.stringify([4, vector.allowDigest]), JSON.stringify([4, vector.allowDigest])])
  })
})
