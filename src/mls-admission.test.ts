import { describe, it, expect, vi } from 'vitest'
import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { base64urlnopad } from '@scure/base'
import {
  MLS_ADMISSION_LABELS, MLS_ADMISSION_CIPHERTEXT_CHARACTERS,
  encodeMlsInvitationV4, readMlsInvitationV4, mlsAdmissionProofTemplatesV4,
  encodeMlsAdmissionRequestV4, decodeMlsAdmissionRequestV4, readMlsAdmissionRequestV4,
  encodeMlsAdmissionAnswerV4, decodeMlsAdmissionAnswerV4, readMlsAdmissionAnswerV4,
  type VerifiedMlsAdmissionRequest, type VerifiedAdmissionAnswer,
} from './mls-admission.js'
import { parseRoomLink } from './link.js'

const NOW = 1791720000
const sk = (n: number) => new Uint8Array(32).fill(n)
const root = sk(1), requestSk = sk(2), account = sk(3), browser = sk(4), engine = sk(5), keeper = sk(6), keeperDevice = sk(7), rz = sk(8), adder = sk(9)
const pk = getPublicKey
const eventArray = (e: Event) => [e.id, e.pubkey, e.created_at, e.kind, e.tags, e.content, e.sig]
const cred = (acct: Uint8Array, device: Uint8Array, tags?: string[][], content = '') => eventArray(finalizeEvent({ kind: 20460, created_at: NOW - 1,
  tags: tags ?? [['d', pk(acct)], ['device', pk(device)], ['expiration', String(NOW + 86400)], ['scope', 'person']], content }, acct))
const fragment = encodeMlsInvitationV4(pk(root), sk(10))
const BOX = '11'.repeat(32)
function core(): unknown[] {
  return [4, MLS_ADMISSION_LABELS[3], readMlsInvitationV4(fragment).invitationId, pk(root), pk(requestSk), '12'.repeat(32), '13'.repeat(32), pk(account), pk(browser), pk(engine), pk(rz), cred(account, engine), BOX, '18446744073709551615', NOW + 3600, NOW, NOW + 90]
}
function proofs(c: unknown[], request?: VerifiedMlsAdmissionRequest): string {
  const templates = mlsAdmissionProofTemplatesV4({ fragment, core: JSON.stringify(c), now: NOW, request })
  return JSON.stringify(templates.map((p, n) => eventArray(finalizeEvent(p.event, request ? [keeper, keeperDevice][n] : [account, browser, engine][n]))))
}
function ceremony() {
  const c = core(), p = proofs(c)
  const wire = encodeMlsAdmissionRequestV4({ fragment, core: JSON.stringify(c), proofs: p, requestSecretKey: requestSk, now: NOW })
  const request = decodeMlsAdmissionRequestV4({ fragment, event: wire, localSecretKey: requestSk, side: 'joiner', now: NOW })
  const host = decodeMlsAdmissionRequestV4({ fragment, event: wire, localSecretKey: root, side: 'root', now: NOW })
  const r = readMlsAdmissionRequestV4(host)
  const allow = [4, MLS_ADMISSION_LABELS[4], 'allow', c[2], c[3], r.eventId, r.digest, c[5], c[6], c[7], c[8], c[9], c[10], c[12], c[13], pk(keeper), pk(keeperDevice), cred(keeper, keeperDevice), pk(adder), BOX, BOX, '14'.repeat(32), '15'.repeat(32), NOW + 1800, NOW + 86400, NOW + 1, NOW + 90]
  const deny = [4, MLS_ADMISSION_LABELS[4], 'deny', c[2], c[3], r.eventId, r.digest, c[5], c[6], NOW + 1, NOW + 90]
  return { c, p, wire, request, host, allow, deny }
}
function requestMutation(wire: string, mutate: (body: unknown[], e: Event) => void): string {
  const e: Event = JSON.parse(wire)
  const base = nip44.v2.utils.getConversationKey(requestSk, pk(root))
  const key = hkdf(sha256, base, sk(10), MLS_ADMISSION_LABELS[1], 32)
  const body: unknown[] = JSON.parse(nip44.v2.decrypt(e.content, key))
  mutate(body, e)
  const empty = JSON.stringify([4, body[1], body[2], ''])
  body[3] = '0'.repeat(16384 - new TextEncoder().encode(empty).length)
  e.content = nip44.v2.encrypt(JSON.stringify(body), key)
  return JSON.stringify(finalizeEvent(e, requestSk))
}

describe('MLS admission v4 isolated evidence codec', () => {
  it('reads canonical links and refuses them in the legacy parser', () => {
    const i = readMlsInvitationV4(fragment)
    expect(i.root).toBe(pk(root)); expect(i.bearer).toEqual(sk(10))
    expect(() => parseRoomLink('https://example.test/#' + fragment)).toThrow()
    i.bearer.fill(0); expect(readMlsInvitationV4(fragment).bearer).toEqual(sk(10))
  })
  it.each([
    'bad=', fragment + '=', 'a'.repeat(1025), base64urlnopad.encode(new TextEncoder().encode(JSON.stringify([3, 'a', pk(root)]))),
    base64urlnopad.encode(new TextEncoder().encode(JSON.stringify([4, base64urlnopad.encode(new Uint8Array(32)), pk(root)]))),
    base64urlnopad.encode(new TextEncoder().encode(JSON.stringify([4, base64urlnopad.encode(sk(10)), '00'.repeat(32)]))),
    base64urlnopad.encode(new TextEncoder().encode(JSON.stringify([4, base64urlnopad.encode(sk(10)), pk(root).toUpperCase()]))),
  ])('refuses malformed or weak link %s', input => expect(() => readMlsInvitationV4(input)).toThrow())
  it('binds three joiner proofs, two keeper proofs and fixed-size Allow/Deny', () => {
    const f = ceremony()
    expect(readMlsAdmissionRequestV4(f.host)).toEqual(readMlsAdmissionRequestV4(f.request))
    const a = encodeMlsAdmissionAnswerV4({ fragment, request: f.host, core: JSON.stringify(f.allow), proofs: proofs(f.allow, f.host), rootSecretKey: root, now: NOW })
    const d = encodeMlsAdmissionAnswerV4({ fragment, request: f.host, core: JSON.stringify(f.deny), proofs: '[]', rootSecretKey: root, now: NOW })
    for (const w of [f.wire, a, d]) expect(JSON.parse(w).content).toHaveLength(MLS_ADMISSION_CIPHERTEXT_CHARACTERS)
    const allow = decodeMlsAdmissionAnswerV4({ fragment, request: f.request, event: a, requestSecretKey: requestSk, now: NOW })
    expect(readMlsAdmissionAnswerV4(allow).decision).toBe('allow')
    expect(readMlsAdmissionAnswerV4(allow).core).toBe(JSON.stringify(f.allow))
    expect(Object.keys(allow)).toEqual([]); expect(Object.isFrozen(allow)).toBe(true)
    expect(readMlsAdmissionAnswerV4(decodeMlsAdmissionAnswerV4({ fragment, request: f.request, event: d, requestSecretKey: requestSk, now: NOW })).decision).toBe('deny')
    expect(requestSk).toEqual(sk(2)); expect(root).toEqual(sk(1))
  })
  it('requires decoder-issued nominal objects and refuses proxy/serialised/structural forgeries', () => {
    const f = ceremony()
    for (const fake of [{}, { ...f.request }, JSON.parse(JSON.stringify(f.request)), new Proxy(f.request, {})]) {
      expect(() => readMlsAdmissionRequestV4(fake as VerifiedMlsAdmissionRequest)).toThrow()
      expect(() => encodeMlsAdmissionAnswerV4({ fragment, request: fake as VerifiedMlsAdmissionRequest, core: JSON.stringify(f.deny), proofs: '[]', rootSecretKey: root, now: NOW })).toThrow()
      expect(() => readMlsAdmissionAnswerV4(fake as VerifiedAdmissionAnswer)).toThrow()
    }
  })
  it.each([0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16])('refuses request field substitution at %i without matching proofs', index => {
    const f = ceremony()
    const bad = requestMutation(f.wire, body => { const c = body[1] as unknown[]; c[index] = index === 13 ? '0' : typeof c[index] === 'number' ? (c[index] as number) + 1 : '16'.repeat(32) })
    expect(() => decodeMlsAdmissionRequestV4({ fragment, event: bad, localSecretKey: root, side: 'root', now: NOW })).toThrow()
  })
  it.each([3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25, 26])('refuses re-encrypted, root-signed answer substitution at %i', index => {
    const f = ceremony()
    const original = encodeMlsAdmissionAnswerV4({ fragment, request: f.host, core: JSON.stringify(f.allow), proofs: proofs(f.allow, f.host), rootSecretKey: root, now: NOW })
    const e: Event = JSON.parse(original)
    const key = hkdf(sha256, nip44.v2.utils.getConversationKey(requestSk, pk(root)), sk(10), MLS_ADMISSION_LABELS[2], 32)
    const body: unknown[] = JSON.parse(nip44.v2.decrypt(e.content, key)), c = body[1] as unknown[]
    c[index] = typeof c[index] === 'number' ? (c[index] as number) + 1 : index === 14 ? '1' : index === 15 ? pk(account) : index === 16 ? pk(engine) : index === 18 ? pk(rz) : '17'.repeat(32)
    const empty = JSON.stringify([4, c, body[2], ''])
    body[3] = '0'.repeat(16384 - new TextEncoder().encode(empty).length)
    e.content = nip44.v2.encrypt(JSON.stringify(body), key)
    const changed = JSON.stringify(finalizeEvent(e, root))
    expect(() => decodeMlsAdmissionAnswerV4({ fragment, request: f.request, event: changed, requestSecretKey: requestSk, now: NOW })).toThrow()
  })
  it.each(['01', '-1', '18446744073709551616', '1e2', ' 2', '0.0'])('refuses noncanonical/out-of-range counter %s', counter => {
    const c = core(); c[13] = counter
    expect(() => mlsAdmissionProofTemplatesV4({ fragment, core: JSON.stringify(c), now: NOW })).toThrow()
  })
  it('refuses duplicate, noncanonical and unknown credential terms before proof preparation', () => {
    for (const change of [
      (t: string[][]) => t.push(['device', pk(engine)]),
      (t: string[][]) => t.push(['scope', 'person']),
      (t: string[][]) => t.push(['other', 'x']),
      (t: string[][]) => { t[2][1] = '0' + t[2][1] },
      (t: string[][]) => { t[1][1] = t[1][1].toUpperCase() },
      (t: string[][]) => t.push(['label', 'x'.repeat(65)]),
      (t: string[][]) => t.push(['seal', '00'.repeat(32)]),
    ]) {
      const c = core(), t = [['d', pk(account)], ['device', pk(engine)], ['expiration', String(NOW + 86400)], ['scope', 'person']]
      change(t); c[11] = cred(account, engine, t)
      expect(() => mlsAdmissionProofTemplatesV4({ fragment, core: JSON.stringify(c), now: NOW })).toThrow()
    }
    const c = core(); c[11] = cred(account, engine, undefined, 'content')
    expect(() => mlsAdmissionProofTemplatesV4({ fragment, core: JSON.stringify(c), now: NOW })).toThrow()
  })
  it('rejects restamped or swapped role proofs and wrong endpoint secrets', () => {
    const f = ceremony(), ps: unknown[][] = JSON.parse(f.p)
    ;[ps[1], ps[2]] = [ps[2], ps[1]]
    expect(() => encodeMlsAdmissionRequestV4({ fragment, core: JSON.stringify(f.c), proofs: JSON.stringify(ps), requestSecretKey: requestSk, now: NOW })).toThrow()
    for (const [side, key] of [['root', requestSk], ['joiner', root]] as const) expect(() => decodeMlsAdmissionRequestV4({ fragment, event: f.wire, localSecretKey: key, side, now: NOW })).toThrow()
    const bad = requestMutation(f.wire, body => { const p = body[2] as unknown[][]; p[0] = eventArray(finalizeEvent({ kind: 20466, created_at: NOW + 1, tags: p[0][4] as string[][], content: p[0][5] as string }, account)) })
    expect(() => decodeMlsAdmissionRequestV4({ fragment, event: bad, localSecretKey: root, side: 'root', now: NOW })).toThrow()
  })
  it('refuses the same root with a different bearer for every answer operation', () => {
    const f = ceremony(), ps = proofs(f.allow, f.host)
    const answer = encodeMlsAdmissionAnswerV4({ fragment, request: f.host, core: JSON.stringify(f.allow), proofs: ps, rootSecretKey: root, now: NOW })
    const different = encodeMlsInvitationV4(pk(root), sk(20))
    expect(() => mlsAdmissionProofTemplatesV4({ fragment: different, core: JSON.stringify(f.allow), request: f.host, now: NOW })).toThrow()
    expect(() => encodeMlsAdmissionAnswerV4({ fragment: different, request: f.host, core: JSON.stringify(f.allow), proofs: ps, rootSecretKey: root, now: NOW })).toThrow()
    expect(() => decodeMlsAdmissionAnswerV4({ fragment: different, request: f.request, event: answer, requestSecretKey: requestSk, now: NOW })).toThrow()
    expect(root).toEqual(sk(1)); expect(requestSk).toEqual(sk(2))
    expect(() => encodeMlsAdmissionAnswerV4({ fragment, request: f.host, core: JSON.stringify(f.allow), proofs: ps, rootSecretKey: requestSk, now: NOW })).toThrow()
    expect(root).toEqual(sk(1)); expect(requestSk).toEqual(sk(2))
  })
  it('wipes owned decoded bearer/fragment buffers when parsing fails', () => {
    const foreign = new Uint8Array(31).fill(17), encoded = base64urlnopad.encode(foreign)
    const link = (bearer: string) => base64urlnopad.encode(new TextEncoder().encode(JSON.stringify([4, bearer, pk(root)])))
    const traces: number[][] = [], fill = Uint8Array.prototype.fill
    const spy = vi.spyOn(Uint8Array.prototype, 'fill').mockImplementation(function(this: Uint8Array, value: number, start?: number, end?: number) {
      if (value === 0) traces.push(Array.from(this))
      return fill.call(this, value, start, end)
    })
    try {
      expect(() => readMlsInvitationV4(link(encoded))).toThrow()
      expect(traces.some(t => t.length === 31 && t.every(b => b === 17))).toBe(true)
      expect(() => readMlsInvitationV4(link(encoded + '='))).toThrow()
      expect(traces.filter(t => t.length > 32).length).toBeGreaterThanOrEqual(2)
      expect(foreign).toEqual(new Uint8Array(31).fill(17))
    } finally { spy.mockRestore() }
  })
  it('checks ceremony deadline on each use, with equality refused', () => {
    const f = ceremony()
    expect(() => decodeMlsAdmissionRequestV4({ fragment, event: f.wire, localSecretKey: root, side: 'root', now: NOW + 90 })).toThrow()
    f.allow[25] = NOW + 90
    expect(() => mlsAdmissionProofTemplatesV4({ fragment, core: JSON.stringify(f.allow), now: NOW, request: f.host })).toThrow()
    expect(() => encodeMlsAdmissionAnswerV4({ fragment, request: f.host, core: JSON.stringify(f.deny), proofs: '[]', rootSecretKey: root, now: NOW + 90 })).toThrow()
  })
  it('refuses oversized/deep/noncanonical input and cached-object boundaries', () => {
    const f = ceremony()
    for (const input of [f.wire + ' '.repeat(32769), '['.repeat(9) + ']'.repeat(9), JSON.parse(f.wire), new Proxy({}, { get() { throw new Error('must not walk') } })]) {
      expect(() => decodeMlsAdmissionRequestV4({ fragment, event: input as string, localSecretKey: root, side: 'root', now: NOW })).toThrow('invalid MLS admission v4')
    }
    expect(() => mlsAdmissionProofTemplatesV4({ fragment, core: JSON.stringify(f.c).replace('[4,', '[4.0,'), now: NOW })).toThrow()
  })
  it('requires exact padding and rejects duplicate outer fields', () => {
    const f = ceremony(), e: Event = JSON.parse(f.wire)
    const key = hkdf(sha256, nip44.v2.utils.getConversationKey(requestSk, pk(root)), sk(10), MLS_ADMISSION_LABELS[1], 32)
    const body: unknown[] = JSON.parse(nip44.v2.decrypt(e.content, key))
    body[3] = (body[3] as string).replace('0', '1')
    e.content = nip44.v2.encrypt(JSON.stringify(body), key)
    const bad = JSON.stringify(finalizeEvent(e, requestSk))
    expect(() => decodeMlsAdmissionRequestV4({ fragment, event: bad, localSecretKey: root, side: 'root', now: NOW })).toThrow()
    const duplicates = f.wire.replace('{', '{"kind":20466,')
    // NIP-01 outer events do not have canonical key order; duplicate keys must
    // still be refused before JSON.parse can silently pick one.
    expect(() => decodeMlsAdmissionRequestV4({ fragment, event: duplicates, localSecretKey: root, side: 'root', now: NOW })).toThrow()
  })
  it('separates direction keys, invitation bearers and root signatures', () => {
    const f = ceremony()
    const wrong = encodeMlsInvitationV4(pk(root), sk(20))
    expect(() => decodeMlsAdmissionRequestV4({ fragment: wrong, event: f.wire, localSecretKey: root, side: 'root', now: NOW })).toThrow()
    const e: Event = JSON.parse(f.wire)
    const key = hkdf(sha256, nip44.v2.utils.getConversationKey(requestSk, pk(root)), sk(10), MLS_ADMISSION_LABELS[2], 32)
    expect(() => nip44.v2.decrypt(e.content, key)).toThrow()
    const a = encodeMlsAdmissionAnswerV4({ fragment, request: f.host, core: JSON.stringify(f.deny), proofs: '[]', rootSecretKey: root, now: NOW })
    const changed = JSON.parse(a); changed.sig = '00'.repeat(64)
    expect(() => decodeMlsAdmissionAnswerV4({ fragment, request: f.request, event: JSON.stringify(changed), requestSecretKey: requestSk, now: NOW })).toThrow()
  })
})
