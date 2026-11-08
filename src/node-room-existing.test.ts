import { expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { signNodeRoom, readNodeRoom, encodeNodeRoomLink, parseNodeRoomLink, encodeNodeJoinRequest, encodeNodeJoinAnswer, decodeNodeJoinAnswer } from './node-room.js'
import { deriveRoom } from './room.js'
import { createDeviceCredential } from './credential.js'
import { localIdentity } from './identity.js'

const now = 1_900_000_000
function fixture(destruct = false) {
  const authoritySk = generateSecretKey(), secret = generateSecretKey(), deviceSk = generateSecretKey()
  const options = { authoritySk, room: deriveRoom(secret).roomId, origin: 'https://node.example', serviceKey: getPublicKey(generateSecretKey()), now,
    existing: { destruct }, turnPorts: { udpTcp: 34790, tls: 53499 } }
  const event = signNodeRoom(options)
  return { authoritySk, secret, deviceSk, options, event, node: readNodeRoom(event, now)! }
}
it.each([false, true])('pins the existing room authority, identity and original destruct=%s policy', destruct => {
  const f = fixture(destruct)
  expect(f.node.existing).toEqual({ destruct })
  expect(f.node.room).toBe(deriveRoom(f.secret).roomId)
  expect(f.node.authority).toBe(getPublicKey(f.authoritySk))
  const body = JSON.parse(f.event.content)
  expect(body).toMatchObject({ profile: 'kithmoot/v1/node-room-existing', files: 'client', destruct })
  expect(parseNodeRoomLink(encodeNodeRoomLink('https://kithmoot.app/j/', f.event, now), now)).toEqual(f.node)
})
it('does not widen the existing strict node-room profile', () => {
  const f = fixture(), old = signNodeRoom({ ...f.options, existing: undefined })
  expect(JSON.parse(old.content)).toMatchObject({ profile: 'kithmoot/v1/node-room', files: 'off' })
  expect(readNodeRoom(old, now)?.existing).toBeUndefined()
  for (const patch of [{ profile: 'kithmoot/v1/node-room', files: 'client' }, { destruct: 'false' }, { files: 'off' }, { profile: 'unknown' }]) {
    const changed = finalizeEvent({ kind: f.event.kind, tags: f.event.tags, created_at: now, content: JSON.stringify({ ...JSON.parse(f.event.content), ...patch }) }, f.authoritySk)
    expect(readNodeRoom(changed, now)).toBeNull()
  }
})
it('requires explicit policy and does not silently accept an existing-room profile as the old profile', () => {
  const f = fixture(), body = JSON.parse(f.event.content)
  delete body.destruct
  const changed = finalizeEvent({ kind: f.event.kind, tags: f.event.tags, created_at: now, content: JSON.stringify(body) }, f.authoritySk)
  expect(readNodeRoom(changed, now)).toBeNull()
  expect(() => signNodeRoom({ ...f.options, existing: { destruct: 'yes' } as never })).toThrow()
})
it('preserves a non-destructing existing room through authenticated node admission', async () => {
  const f = fixture(), participant = localIdentity(generateSecretKey())
  const credential = await createDeviceCredential({ identity: participant, devicePubkey: getPublicKey(f.deviceSk), roomId: f.node.room, expiresAt: now + 3600, now: () => now })
  const request = encodeNodeJoinRequest({ node: f.node, deviceSk: f.deviceSk, credential, now })
  const grant = finalizeEvent({ kind: 27541, created_at: now, content: '', tags: [['t', 'grant'], ['grant', '01'.repeat(16)], ['d', f.node.room], ['device', getPublicKey(f.deviceSk)], ['server', 'node.example'], ['scope', 'turn'], ['scope', 'relay-read'], ['scope', 'relay-write'], ['status', 'active'], ['expiration', String(now + 3600)]] }, f.authoritySk)
  const answer = encodeNodeJoinAnswer({ node: f.node, authoritySk: f.authoritySk, request: request.event, now, admission: { roomSecret: f.secret, epochHint: 3, grant } })
  const read = decodeNodeJoinAnswer({ node: f.node, deviceSk: f.deviceSk, event: answer, requestId: request.requestId, requestExpiresAt: request.expiresAt, now })
  expect(read && read !== 'denied' && read.destruct).toBe(false)
  expect(read && read !== 'denied' && read.secret).toEqual(f.secret)
  expect(read && read !== 'denied' && read.epochHint).toBe(3)
})
