import { expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { hexToBytes } from '@noble/hashes/utils'
import { withStubbedRandomness } from './lib/determinism.mjs'
import { signNodeRoom, readNodeRoom, parseNodeRoomLink, encodeNodeJoinRequest, decodeNodeJoinRequest, encodeNodeJoinAnswer, decodeNodeJoinAnswer } from '../src/node-room.js'
import { parseRoomLink } from '../src/link.js'
import { signNodeClosure, readNodeClosure, recoverNodeClosure, readNodeCloseReceipt } from '../src/node-room.js'
const v = JSON.parse(readFileSync(new URL('./node-room-vectors.json', import.meta.url), 'utf8'))
const wire = (value: unknown) => JSON.parse(JSON.stringify(value))
it('recomputes the byte-identical node descriptor and NIP-59 envelopes from recorded randomness', () => {
  const authoritySk = hexToBytes(v.keys.authority), deviceSk = hexToBytes(v.keys.device), now = v.now
  const node = readNodeRoom(v.descriptor, now)!
  expect(node).not.toBeNull(); expect(parseNodeRoomLink(v.link, now)).toEqual(node)
  expect(wire(withStubbedRandomness(v.closureRandom.map(hexToBytes), () => signNodeClosure({ node, authoritySk, operation: v.closureProof.operation, now })))).toEqual(v.closure)
  expect(readNodeClosure(v.closure, node, now)).toEqual(v.closureProof)
  expect(recoverNodeClosure(v.closureProof, node, now)).toEqual(v.closure)
  expect(readNodeCloseReceipt(v.receipt, node, v.closureProof.operation, now)).toMatchObject({ callsRevoked: true, relayPurged: true, eventsDeleted: 3 })
  expect(readNodeCloseReceipt(v.receipt, node, 'ff'.repeat(16), now)).toBeNull()
  expect(readNodeClosure(v.receipt, node, now)).toBeNull()
  expect(() => parseRoomLink(v.link)).toThrow('unsupported version')
  expect(wire(withStubbedRandomness(v.descriptorRandom.map(hexToBytes), () => signNodeRoom({ authoritySk, room: node.room, serviceKey: node.serviceKey, origin: node.origin, now })))).toEqual(v.descriptor)
  expect(wire(withStubbedRandomness(v.requestRandom.map(hexToBytes), () => encodeNodeJoinRequest({ node, deviceSk, credential: v.credential, name: 'Guest', now })))).toEqual(v.request)
  const request = decodeNodeJoinRequest({ node, authoritySk, event: v.request.event, now: now + 1 })!
  expect(request.id).toBe(v.request.requestId); expect(request.device).toBe(v.grant.tags.find((t: string[]) => t[0] === 'device')[1])
  expect(wire(withStubbedRandomness(v.answerRandom.map(hexToBytes), () => encodeNodeJoinAnswer({ node, authoritySk, request: v.request.event, now: now + 1,
    admission: { roomSecret: hexToBytes(v.keys.secret), epochHint: 3, grant: v.grant } })))).toEqual(v.answer)
  expect(wire(withStubbedRandomness(v.deniedRandom.map(hexToBytes), () => encodeNodeJoinAnswer({ node, authoritySk, request: v.request.event, now: now + 1 })))).toEqual(v.denied)
  const context = { node, deviceSk, requestId: v.request.requestId, requestExpiresAt: v.request.expiresAt, now: now + 2 }
  expect(decodeNodeJoinAnswer({ ...context, event: v.denied })).toBe('denied')
  expect(decodeNodeJoinAnswer({ ...context, event: v.answer })).toMatchObject({ secret: hexToBytes(v.keys.secret), grant: v.grant, epochHint: 3 })
  expect(decodeNodeJoinAnswer({ ...context, event: v.answer, requestId: 'ff'.repeat(32) })).toBeNull()
  expect(decodeNodeJoinAnswer({ ...context, event: v.answer, now: now + 91 })).toBeNull()
  expect(decodeNodeJoinAnswer({ ...context, event: { ...v.answer, content: v.answer.content + 'x' } })).toBeNull()
})
