import { expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { signNodeRoom, readNodeRoom } from './node-room.js'
import { signNodeMigrationPreparation, readNodeMigrationPreparation, signNodeMigrationReady, readNodeMigrationReady,
  signNodeMigrationCommit, readNodeMigrationCommit, nodeMigrationDigest } from './node-migration.js'

const now = 1_900_000_000
function fixture() {
  const authoritySk = generateSecretKey(), devices = [generateSecretKey(), generateSecretKey(), generateSecretKey()]
  const node = readNodeRoom(signNodeRoom({ authoritySk, room: 'ab'.repeat(32), origin: 'https://node.example', serviceKey: getPublicKey(generateSecretKey()), now, existing: { destruct: false } }), now)!
  const endpoints = devices.map((sk, i) => ({ device: getPublicKey(sk), sid: `client-session-${i}` }))
  const prepare = signNodeMigrationPreparation({ node, authoritySk, operation: 'cd'.repeat(16), endpoints, epoch: 3, now })
  const preparation = readNodeMigrationPreparation(prepare, now, node.authority)!
  function ready(i: number, at = now + 1) {
    const sk = devices[i], grant = finalizeEvent({ kind: 27541, created_at: now, content: '', tags: [['t','grant'],['grant', `${i + 1}`.padStart(32,'0')],['d',node.room],['device',getPublicKey(sk)],['server','node.example'],['scope','turn'],['scope','relay-read'],['scope','relay-write'],['status','active'],['expiration',String(now + 3600)]] }, authoritySk)
    return signNodeMigrationReady({ preparation, deviceSk: sk, sid: endpoints[i].sid, grant, history: { events: 2, digest: nodeMigrationDigest(['01'.repeat(32),'02'.repeat(32)]) }, now: at })
  }
  return { authoritySk, devices, node, endpoints, prepare, preparation, ready }
}
it('requires desktop, Android and web readiness before committing the same room and epoch', () => {
  const f=fixture(), ready=[f.ready(0),f.ready(1),f.ready(2)]
  const commit=signNodeMigrationCommit({ preparation:f.preparation, authoritySk:f.authoritySk, ready, now:now+2 })
  const result=readNodeMigrationCommit(commit,now+3,f.node.authority)!
  expect(result.preparation.node.room).toBe(f.node.room)
  expect(result.preparation.epoch).toBe(3)
  expect(result.ready.map(r=>r.endpoint).sort((a,b)=>a.device.localeCompare(b.device))).toEqual([...f.endpoints].sort((a,b)=>a.device.localeCompare(b.device)))
  expect(result.preparation.node.existing).toEqual({destruct:false})
  for(const list of [ready.slice(0,2),[ready[0],ready[0],ready[2]]]) expect(()=>signNodeMigrationCommit({preparation:f.preparation,authoritySk:f.authoritySk,ready:list,now:now+2})).toThrow()
})
it('treats two sessions with the same device key as different required endpoints', () => {
  const f=fixture(), endpoints=[f.endpoints[0],{...f.endpoints[0],sid:'another-tab-session'}]
  const preparation=readNodeMigrationPreparation(signNodeMigrationPreparation({node:f.node,authoritySk:f.authoritySk,operation:'ff'.repeat(16),endpoints,epoch:3,now}),now,f.node.authority)!
  const first=f.ready(0)
  expect(readNodeMigrationReady(first,preparation,now+2)).toBeNull()
  expect(()=>signNodeMigrationCommit({preparation,authoritySk:f.authoritySk,ready:[first,first],now:now+2})).toThrow()
})
it('refuses stale, wrong-signer, wrong-node, duplicate and invalid endpoint preparations', () => {
  const f=fixture()
  expect(readNodeMigrationPreparation(f.prepare,now+600,f.node.authority)).toBeNull()
  expect(readNodeMigrationPreparation(f.prepare,now,getPublicKey(f.devices[0]))).toBeNull()
  for(const endpoints of [[f.endpoints[0],f.endpoints[0]],[],[{...f.endpoints[0],sid:''}]]) expect(()=>signNodeMigrationPreparation({node:f.node,authoritySk:f.authoritySk,operation:'cd'.repeat(16),endpoints,epoch:3,now})).toThrow()
  expect(()=>signNodeMigrationPreparation({node:f.node,authoritySk:f.devices[0],operation:'cd'.repeat(16),endpoints:f.endpoints,epoch:3,now})).toThrow()
})
it('binds readiness to the exact preparation, device, session and active node grant', () => {
  const f=fixture(), ready=f.ready(0), read=readNodeMigrationReady(ready,f.preparation,now+2)!
  expect(read.endpoint).toEqual(f.endpoints[0])
  expect(read.history.events).toBe(2)
  const other=fixture()
  expect(readNodeMigrationReady(ready,other.preparation,now+2)).toBeNull()
  for(const patch of [{sid:f.endpoints[1].sid},{preparation:'00'.repeat(32)},{history:{events:2,digest:'invalid'}}]) {
    const forged=finalizeEvent({kind:ready.kind,created_at:ready.created_at,tags:ready.tags,content:JSON.stringify({...JSON.parse(ready.content),...patch})},f.devices[0])
    expect(readNodeMigrationReady(forged,f.preparation,now+2)).toBeNull()
  }
  const revoked=finalizeEvent({kind:27541,created_at:now,content:'',tags:[['t','grant'],['grant','01'.repeat(16)],['d',f.node.room],['device',f.endpoints[0].device],['server','node.example'],['scope','turn'],['scope','relay-read'],['scope','relay-write'],['status','revoked'],['expiration',String(now+3600)]]},f.authoritySk)
  expect(()=>signNodeMigrationReady({preparation:f.preparation,deviceSk:f.devices[0],sid:f.endpoints[0].sid,grant:revoked,history:{events:0,digest:nodeMigrationDigest([])},now:now+1})).toThrow()
})
it('allows recovery of a committed transition after preparation expiry, without allowing a late commit', () => {
  const f=fixture(), ready=[f.ready(0),f.ready(1),f.ready(2)]
  const commit=signNodeMigrationCommit({preparation:f.preparation,authoritySk:f.authoritySk,ready,now:now+2})
  expect(readNodeMigrationCommit(commit,now+3600,f.node.authority)).not.toBeNull()
  expect(readNodeMigrationCommit(commit,now+30*86400+2,f.node.authority)).toBeNull()
  expect(()=>signNodeMigrationCommit({preparation:f.preparation,authoritySk:f.authoritySk,ready,now:now+600})).toThrow()
  const body=JSON.parse(commit.content); body.ready=body.ready.slice(0,2)
  const incomplete=finalizeEvent({kind:commit.kind,created_at:commit.created_at,tags:commit.tags,content:JSON.stringify(body)},f.authoritySk)
  expect(readNodeMigrationCommit(incomplete,now+3,f.node.authority)).toBeNull()
})
it('hashes an exact unique set of original event ids without order dependence', () => {
  const a='01'.repeat(32),b='02'.repeat(32)
  expect(nodeMigrationDigest([a,b,a])).toBe(nodeMigrationDigest([b,a]))
  expect(nodeMigrationDigest([a])).not.toBe(nodeMigrationDigest([b]))
  expect(()=>nodeMigrationDigest(['not-an-event-id'])).toThrow()
})
