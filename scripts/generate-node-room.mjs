// Synthetic deterministic fixtures. Never use these keys in a real room.
import { writeFileSync } from 'node:fs'
import { bytesToHex } from '@noble/hashes/utils'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { getPublicKey } from 'nostr-tools/pure'
import { deriveSecretKey, seed32, finalizeDeterministic, withStubbedRandomness } from '../vectors/lib/determinism.mjs'
import { deriveRoom } from '../dist/index.js'
import { signNodeRoom, readNodeRoom, encodeNodeRoomLink, encodeShortNodeRoomLink, inspectNodeRoomLink, encodeNodeJoinRequest, encodeNodeJoinAnswer, signNodeClosure, readNodeClosure, signNodeRetirement } from '../dist/node-room.js'

const now = 1_900_000_000, authority = deriveSecretKey('node/authority'), device = deriveSecretKey('node/device'), participant = deriveSecretKey('node/participant')
const serviceSk = deriveSecretKey('node/service')
const secret = seed32('node/room-secret'), room = deriveRoom(secret).roomId, serviceKey = getPublicKey(serviceSk)
const wire = value => JSON.parse(JSON.stringify(value))
const descriptorRandom = [seed32('node/descriptor-aux')]
const descriptor = wire(withStubbedRandomness(descriptorRandom, () => signNodeRoom({ authoritySk: authority, room, origin: 'https://node.example', serviceKey, now })))
const node = readNodeRoom(descriptor, now)
const credential = finalizeDeterministic({ kind: 20460, created_at: now, content: '', tags: [['d', room], ['device', getPublicKey(device)], ['expiration', String(now + 3600)]] }, participant, seed32('node/credential-aux'))
const grant = finalizeDeterministic({ kind: 27541, created_at: now, content: '', tags: [['t', 'grant'], ['grant', '01'.repeat(16)], ['d', room], ['device', getPublicKey(device)],
  ['server', 'node.example'], ['scope', 'turn'], ['scope', 'relay-read'], ['scope', 'relay-write'], ['status', 'active'], ['expiration', String(now + 3600)]] }, authority, seed32('node/grant-aux'))
const wrapRandom = label => [seed32(`${label}/seal-nonce`), seed32(`${label}/seal-aux`), hkdf(sha256, seed32(`${label}/outer-seed`), undefined, 'outer scalar', 48), seed32(`${label}/outer-nonce`), seed32(`${label}/outer-aux`)]
const requestRandom = [seed32('node/request-id'), ...wrapRandom('node/request')]
const request = wire(withStubbedRandomness(requestRandom, () => encodeNodeJoinRequest({ node, deviceSk: device, credential, name: 'Guest', now })))
const answerRandom = wrapRandom('node/answer')
const answer = wire(withStubbedRandomness(answerRandom, () => encodeNodeJoinAnswer({ node, authoritySk: authority, request: request.event, now: now + 1, admission: { roomSecret: secret, epochHint: 3, grant } })))
const deniedRandom = wrapRandom('node/denied')
const denied = wire(withStubbedRandomness(deniedRandom, () => encodeNodeJoinAnswer({ node, authoritySk: authority, request: request.event, now: now + 1 })))
const closureRandom = [seed32('node/close-aux')]
const closure = wire(withStubbedRandomness(closureRandom, () => signNodeClosure({ node, authoritySk: authority, operation: 'ab'.repeat(16), now })))
const retirementRandom = [seed32('node/retirement-nonce'), seed32('node/retirement-aux')]
const retirement = wire(withStubbedRandomness(retirementRandom, () => signNodeRetirement({ node, authoritySk: authority, roomSecret: secret, operation: 'ab'.repeat(16), now })))
const receipt = finalizeDeterministic({ kind: 27544, created_at: now, tags: [['operation', 'ab'.repeat(16)], ['expiration', String(now + 30 * 86400)]],
  content: JSON.stringify({ v: 1, operation: 'ab'.repeat(16), published: true, callsRevoked: true, relayPurged: true, eventsDeleted: 3, completedAt: now }) }, serviceSk, seed32('node/receipt-aux'))
const record = { profile: 'node-room/1', linkVersion: 6, note: 'Synthetic deterministic keys. Codec evidence only, not backend or device acceptance.', now,
  keys: { authority: bytesToHex(authority), device: bytesToHex(device), participant: bytesToHex(participant), secret: bytesToHex(secret) },
  descriptor, descriptorRandom: descriptorRandom.map(bytesToHex), link: encodeNodeRoomLink('https://app.example/j/', descriptor, now), credential, grant,
  request, requestRandom: requestRandom.map(bytesToHex), answer, answerRandom: answerRandom.map(bytesToHex), denied, deniedRandom: deniedRandom.map(bytesToHex),
  closure, closureRandom: closureRandom.map(bytesToHex), closureProof: readNodeClosure(closure, node, now),
  retirement, retirementRandom: retirementRandom.map(bytesToHex),
  receipt,
  refusals: ['wrong-request-id', 'wrong-device-key', 'wrong-node', 'tampered-descriptor', 'expired-answer', 'forged-grant', 'legacy-parser-refuses-link'] }
const portsRandom = [seed32('node/ports-descriptor-aux')], turnPorts = { udpTcp: 34790, tls: 53499 }
const portsDescriptor = wire(withStubbedRandomness(portsRandom, () => signNodeRoom({ authoritySk: authority, room, origin: 'https://node.example', serviceKey, now, turnPorts })))
const portsNode = readNodeRoom(portsDescriptor, now)
record.customPorts = { turnPorts, descriptor: portsDescriptor, descriptorRandom: portsRandom.map(bytesToHex), link: encodeNodeRoomLink('https://app.example/j/', portsDescriptor, now), iceUrls: portsNode.iceUrls, turnUrls: portsNode.turnUrls }
const shortRandom = [seed32('node/short-descriptor-aux')], endsAt = now + 86400
const shortPolicy = { tier: 'open', members: [getPublicKey(device), getPublicKey(participant)], quiet: true }
const shortDescriptor = wire(withStubbedRandomness(shortRandom, () => signNodeRoom({ authoritySk: authority, room, origin: 'https://node.example', serviceKey, now,
  endsAt, turnPorts, existing: { destruct: true, policy: shortPolicy } })))
const shortLink = encodeShortNodeRoomLink('https://app.example/j/', shortDescriptor, now)
record.short = { linkVersion: 7, note: 'The same signed records as a version 7 link. A reader rebuilds id, kind, tags and content and must reach the identical event id.',
  link: encodeShortNodeRoomLink('https://app.example/j/', descriptor, now), customPortsLink: encodeShortNodeRoomLink('https://app.example/j/', portsDescriptor, now),
  existing: { policy: shortPolicy, endsAt, descriptor: shortDescriptor, descriptorRandom: shortRandom.map(bytesToHex), link: shortLink, longLink: encodeNodeRoomLink('https://app.example/j/', shortDescriptor, now) },
  states: [{ now, state: 'open' }, { now: endsAt - 1, state: 'open' }, { now: endsAt, state: 'ended', endsAt }, { now: now - 31, state: 'early', createdAt: now }]
    .map(s => { const seen = inspectNodeRoomLink(shortLink, s.now); if (seen?.state !== s.state) throw Error(`state at ${s.now}`); return s }),
  refusals: ['any-single-bit-change', 'truncated', 'trailing-byte', 'unknown-flag', 'existing-flags-on-new-room', 'legacy-parser-refuses-link'] }
writeFileSync(new URL('../vectors/node-room-vectors.json', import.meta.url), JSON.stringify(record, null, 2) + '\n')
console.log('Node-room v6 and v7 descriptor, sealed request, answer and refusal vectors generated')
