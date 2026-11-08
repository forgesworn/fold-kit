// Synthetic keys only. These fixtures carry no usable deployment authority.
import { writeFileSync } from 'node:fs'
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure'
import { deriveRoom } from '../dist/room.js'
import { signNodeRoom, readNodeRoom } from '../dist/node-room.js'
import { encodeNodeMigrationFrames, signNodeMigrationPreparation, readNodeMigrationPreparation, signNodeMigrationReady, signNodeMigrationCommit, nodeMigrationDigest } from '../dist/node-migration.js'
const key = n => new Uint8Array(32).fill(n), hex = bytes => Buffer.from(bytes).toString('hex')
const now = 1_900_000_000, authority = key(1), service = key(7), secret = key(9), devices = [key(2),key(3),key(4)]
const room = deriveRoom(secret).roomId
const nodeEvent = signNodeRoom({ authoritySk:authority, room, origin:'https://node.example', serviceKey:getPublicKey(service), now,
  existing:{destruct:false}, turnPorts:{udpTcp:34790,tls:53499} })
const node = readNodeRoom(nodeEvent,now)
const endpoints = devices.map((sk,i)=>({device:getPublicKey(sk),sid:`client-session-${i}`}))
const preparation = signNodeMigrationPreparation({ node, authoritySk:authority, operation:'cd'.repeat(16), endpoints, epoch:3, now })
const parsed = readNodeMigrationPreparation(preparation,now,node.authority)
const history = { events:2, digest:nodeMigrationDigest(['01'.repeat(32),'02'.repeat(32)]) }
const grants = devices.map((sk,i)=>finalizeEvent({kind:27541,created_at:now,content:'',tags:[['t','grant'],['grant',String(i+1).padStart(32,'0')],['d',room],['device',getPublicKey(sk)],['server','node.example'],['scope','turn'],['scope','relay-read'],['scope','relay-write'],['status','active'],['expiration',String(now+3600)]]},authority))
const ready = devices.map((sk,i)=>signNodeMigrationReady({preparation:parsed,deviceSk:sk,sid:endpoints[i].sid,grant:grants[i],history,now:now+1}))
const commit=signNodeMigrationCommit({preparation:parsed,authoritySk:authority,ready,now:now+2})
writeFileSync(new URL('../vectors/node-migration-vectors.json',import.meta.url),JSON.stringify({profile:'node-migration/1',now,keys:{authority:hex(authority),secret:hex(secret),devices:devices.map(hex)},node:nodeEvent,endpoints,preparation,grants,history,ready,commit,frames:encodeNodeMigrationFrames(commit)},null,2)+'\n')
