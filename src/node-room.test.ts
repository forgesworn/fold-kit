import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey, finalizeEvent, verifiedSymbol } from 'nostr-tools/pure'
import { signNodeRoom, readNodeRoom, encodeNodeRoomLink, parseNodeRoomLink, encodeNodeJoinRequest, decodeNodeJoinRequest,
  encodeNodeJoinAnswer, decodeNodeJoinAnswer, withNodeRoomExpiration, verifyNodeRoomGrant } from './node-room.js'
import { signNodeClosure, readNodeClosure, recoverNodeClosure, signNodeRetirement, readNodeRetirement, readNodeCloseReceipt, readNodeOperationReceipt } from './node-room.js'
import { deriveRoom } from './room.js'
import { parseRoomLink } from './link.js'
import { createDeviceCredential } from './credential.js'
import { localIdentity } from './identity.js'

const now = 1_900_000_000
async function fixture() {
  const authority = generateSecretKey(), service = generateSecretKey(), device = generateSecretKey(), secret = generateSecretKey(), room = deriveRoom(secret).roomId
  const event = signNodeRoom({ authoritySk: authority, room, serviceKey: getPublicKey(service), origin: 'https://node.example', now })
  const node = readNodeRoom(event, now)!
  const credential = await createDeviceCredential({ identity: localIdentity(generateSecretKey()), devicePubkey: getPublicKey(device), roomId: room, expiresAt: now + 3600, now: () => now })
  const request = encodeNodeJoinRequest({ node, deviceSk: device, credential, now, name: 'Guest' })
  const grant = finalizeEvent({ kind: 27541, created_at: now, content: '', tags: [['t', 'grant'], ['grant', '01'.repeat(16)], ['d', room],
    ['device', getPublicKey(device)], ['server', 'node.example'], ['scope', 'turn'], ['scope', 'relay-read'], ['scope', 'relay-write'],
    ['status', 'active'], ['expiration', String(now + 3600)]] }, authority)
  const answer = encodeNodeJoinAnswer({ node, authoritySk: authority, request: request.event, now: now + 1, admission: { roomSecret: secret, epochHint: 3, grant } })
  return { authority, service, device, secret, room, event, node, credential, request, grant, answer }
}
describe('ask-only node rooms', () => {
  it('retires the v6 link inside the admitted room without making a legacy bearer secret', async () => {
    const f = await fixture(), operation = 'ab'.repeat(16)
    const retired = signNodeRetirement({ node: f.node, authoritySk: f.authority, roomSecret: f.secret, operation, now })
    expect(readNodeRetirement(retired, f.node, f.secret, now)).toEqual({ operation, at: now })
    expect(retired.kind).toBe(1461); expect(retired.tags).toEqual([['d', f.room], ['expiration', String(now + 30 * 86400)]])
    expect(retired.content).not.toContain(operation); expect(retired.content).not.toContain(f.node.event.id)
    expect(readNodeRetirement(retired, f.node, generateSecretKey(), now)).toBeNull()
    expect(readNodeRetirement({ ...retired, content: retired.content + 'x', [verifiedSymbol]: true }, f.node, f.secret, now)).toBeNull()
    expect(readNodeRetirement(retired, f.node, f.secret, now + 30 * 86400)).toBeNull()
    const other = readNodeRoom(signNodeRoom({ authoritySk: f.authority, room: f.room, serviceKey: f.node.serviceKey, origin: 'https://other.example', now }), now)!
    expect(readNodeRetirement(retired, other, f.secret, now)).toBeNull()
    expect(() => signNodeRetirement({ node: f.node, authoritySk: f.device, roomSecret: f.secret, operation, now })).toThrow()
    expect(readNodeClosure(retired, f.node, now)).toBeNull()
  })
  it('clamps the retirement to the signed room end', async () => {
    const f = await fixture(), endsAt = now + 60
    const node = readNodeRoom(signNodeRoom({ authoritySk: f.authority, room: f.room, serviceKey: f.node.serviceKey, origin: f.node.origin, endsAt, now }), now)!
    const retired = signNodeRetirement({ node, authoritySk: f.authority, roomSecret: f.secret, operation: 'ab'.repeat(16), now })
    expect(retired.tags).toContainEqual(['expiration', String(endsAt)])
    expect(readNodeRetirement(retired, node, f.secret, endsAt - 1)).not.toBeNull()
    expect(readNodeRetirement(retired, node, f.secret, endsAt)).toBeNull()
  })
  it('verifies a complete operation using only the paired public service key and random id', async () => {
    const f = await fixture(), operation = 'ab'.repeat(16)
    const template = { kind: 27544, created_at: now, tags: [['operation', operation], ['expiration', String(now + 30 * 86400)]],
      content: JSON.stringify({ v: 1, operation, published: true, callsRevoked: true, relayPurged: true, eventsDeleted: 3, completedAt: now }) }
    const receipt = finalizeEvent(template, f.service)
    expect(readNodeOperationReceipt(receipt, f.node.serviceKey, operation, now)).toEqual(readNodeCloseReceipt(receipt, f.node, operation, now))
    expect(readNodeOperationReceipt(receipt, f.node.serviceKey, operation, now)).toMatchObject({ callsRevoked: true, relayPurged: true })
    expect(readNodeOperationReceipt(receipt, f.node.authority, operation, now)).toBeNull()
    expect(readNodeOperationReceipt(receipt, f.node.serviceKey, 'cd'.repeat(16), now)).toBeNull()
    expect(readNodeOperationReceipt(receipt, f.node.serviceKey, operation, now + 30 * 86400)).toBeNull()
    const incomplete = finalizeEvent({ ...template, content: template.content.replace('"relayPurged":true', '"relayPurged":false') }, f.service)
    expect(readNodeOperationReceipt(incomplete, f.node.serviceKey, operation, now)).toBeNull()
    expect(readNodeClosure(receipt, f.node, now)).toBeNull()
  })
  it('writes v6 links with a signed node record and no traffic key or bearer welcome', async () => {
    const f = await fixture(), link = encodeNodeRoomLink('https://app.example/j/', f.event, now)
    expect(parseNodeRoomLink(link, now)).toEqual(f.node)
    expect(() => parseRoomLink(link)).toThrow('unsupported version')
    const body = JSON.stringify(JSON.parse(Buffer.from(new URL(link).hash.slice(1), 'base64url').toString()))
    expect(body).not.toContain(Buffer.from(f.secret).toString('base64url'))
    expect(body).not.toContain('secret')
    expect(f.node.turnUrls).toHaveLength(4)
    expect(f.node.turnUrls[3]).toBe('turns:turn.node.example:443?transport=tcp')
  })
  it('verifies the device credential and seals an admitted key and grant only to that device', async () => {
    const f = await fixture()
    const request = decodeNodeJoinRequest({ node: f.node, authoritySk: f.authority, event: f.request.event, now: now + 1 })!
    expect(request.device).toBe(getPublicKey(f.device)); expect(request.credential).toEqual(JSON.parse(JSON.stringify(f.credential)))
    const result = decodeNodeJoinAnswer({ node: f.node, deviceSk: f.device, event: f.answer, requestId: f.request.requestId, requestExpiresAt: f.request.expiresAt, now: now + 2 })
    expect(result).toMatchObject({ persistent: true, destruct: true, epoch: 0, epochHint: 3, storage: [], grant: JSON.parse(JSON.stringify(f.grant)), secret: f.secret, relays: ['wss://node.example/events'] })
    expect(f.request.event.pubkey).not.toBe(getPublicKey(f.device)); expect(f.answer.pubkey).not.toBe(getPublicKey(f.authority))
    expect(f.answer.tags.map(t => t[0])).toEqual(['p', 'expiration'])
  })
  it('rejects another request, recipient, authority, descriptor and expired answer', async () => {
    const f = await fixture()
    const good = { node: f.node, deviceSk: f.device, event: f.answer, requestId: f.request.requestId, requestExpiresAt: f.request.expiresAt, now: now + 2 }
    for (const patch of [{ requestId: 'ab'.repeat(32) }, { deviceSk: generateSecretKey() }, { now: now + 91 },
      { node: { ...f.node, authority: getPublicKey(generateSecretKey()) } }, { event: { ...f.answer, content: f.answer.content + 'x', [verifiedSymbol]: true } }]) {
      expect(decodeNodeJoinAnswer({ ...good, ...patch })).toBeNull()
    }
    const other = readNodeRoom(signNodeRoom({ authoritySk: f.authority, room: f.room, origin: 'https://other.example', serviceKey: f.node.serviceKey, now }), now)!
    expect(decodeNodeJoinAnswer({ ...good, node: other })).toBeNull()
    expect(decodeNodeJoinRequest({ node: other, authoritySk: f.authority, event: f.request.event, now })).toBeNull()
  })
  it('refuses a missing, revoked, foreign-server or mismatched-device grant before revealing the traffic key', async () => {
    const f = await fixture()
    for (const [name, value] of [['status', 'revoked'], ['server', 'other.example'], ['device', getPublicKey(generateSecretKey())], ['d', 'ab'.repeat(32)]]) {
      const grant = finalizeEvent({ kind: 27541, created_at: now, content: '', tags: f.grant.tags.map(t => t[0] === name ? [name!, value!] : t) }, f.authority)
      expect(verifyNodeRoomGrant(grant, f.node, getPublicKey(f.device), now)).toBe(false)
      expect(() => encodeNodeJoinAnswer({ node: f.node, authoritySk: f.authority, request: f.request.event, now: now + 1, admission: { roomSecret: f.secret, epochHint: 0, grant } })).toThrow()
    }
  })
  it('rejects route changes, added public fallbacks, invalid signed records and cached signature verdicts', async () => {
    const f = await fixture()
    expect(readNodeRoom({ ...f.event, content: f.event.content.replace('relay-only', 'direct'), [verifiedSymbol]: true }, now)).toBeNull()
    const changed = finalizeEvent({ kind: f.event.kind, created_at: now, tags: f.event.tags, content: f.event.content.replace('"files":"off"', '"files":"off","fallback":"wss://public.example"') }, f.authority)
    expect(readNodeRoom(changed, now)).toBeNull()
    for (const origin of ['https://127.0.0.1', 'https://node.local', 'http://node.example', 'https://node.example/path', 'https://node.example:8443']) {
      expect(() => signNodeRoom({ authoritySk: f.authority, room: f.room, serviceKey: f.node.serviceKey, origin, now })).toThrow()
    }
  })
  it('supports an authenticated refusal without a key or grant and stamps every node event with bounded expiry', async () => {
    const f = await fixture(), answer = encodeNodeJoinAnswer({ node: f.node, authoritySk: f.authority, request: f.request.event, now })
    expect(decodeNodeJoinAnswer({ node: f.node, deviceSk: f.device, event: answer, requestId: f.request.requestId, requestExpiresAt: f.request.expiresAt, now })).toBe('denied')
    expect(withNodeRoomExpiration([], now)).toEqual([['expiration', String(now + 30 * 86400)]])
    expect(withNodeRoomExpiration([['expiration', String(now + 5)]], now, now + 60)).toEqual([['expiration', String(now + 5)]])
  })
  it('requires an explicit authority-signed closure before device deletion, not a reset or a node refusal', async () => {
    const f = await fixture(), operation = 'ab'.repeat(16)
    const closed = signNodeClosure({ node: f.node, authoritySk: f.authority, operation, now })
    const proof = readNodeClosure(closed, f.node, now)!
    expect(proof).not.toHaveProperty('pubkey'); expect(proof).not.toHaveProperty('room')
    expect(recoverNodeClosure(proof, f.node, now + 5)).toEqual(JSON.parse(JSON.stringify(closed)))
    expect(recoverNodeClosure({ ...proof, operation: 'cd'.repeat(16) }, f.node, now)).toBeNull()
    expect(recoverNodeClosure(proof, f.node, now + 30 * 86400)).toBeNull()
    const reset = finalizeEvent({ kind: 27541, created_at: now, content: '', tags: [['t', 'reset'], ['d', f.room], ['server', 'node.example'], ['expiration', String(now + 90 * 86400)]] }, f.authority)
    expect(readNodeClosure(reset, f.node, now)).toBeNull()
    const forged = finalizeEvent({ kind: closed.kind, created_at: now, content: '', tags: closed.tags }, generateSecretKey())
    expect(readNodeClosure(forged, f.node, now)).toBeNull()
  })
})
