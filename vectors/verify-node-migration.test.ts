import { readFileSync } from 'node:fs'
import { expect, it } from 'vitest'
import { hexToBytes } from '@noble/hashes/utils'
import { readNodeRoom, signNodeRoom } from '../src/node-room.js'
import { nodeMigrationDigest, readNodeMigrationPreparation, readNodeMigrationReady, readNodeMigrationCommit,
  signNodeMigrationPreparation, signNodeMigrationReady, signNodeMigrationCommit } from '../src/node-migration.js'

const v = JSON.parse(readFileSync(new URL('./node-migration-vectors.json', import.meta.url), 'utf8'))
it('pins the same signed existing-room handover consumed by Android', () => {
  const authoritySk = hexToBytes(v.keys.authority), node = readNodeRoom(v.node, v.now)!
  expect(node.existing).toEqual({ destruct: false })
  expect(signNodeRoom({ authoritySk, room: node.room, origin: node.origin, serviceKey: node.serviceKey,
    now: v.now, existing: node.existing, turnPorts: node.turnPorts }).id).toBe(node.event.id)
  const preparation = readNodeMigrationPreparation(v.preparation, v.now, node.authority)!
  expect(signNodeMigrationPreparation({ node, authoritySk, operation: preparation.operation,
    endpoints: preparation.endpoints, epoch: preparation.epoch, now: v.now }).id).toBe(preparation.event.id)
  for (const [index, raw] of v.ready.entries()) {
    const ready = readNodeMigrationReady(raw, preparation, v.now + 2)!
    expect(signNodeMigrationReady({ preparation, deviceSk: hexToBytes(v.keys.devices[index]), sid: ready.endpoint.sid,
      grant: ready.grant, history: ready.history, now: v.now + 1 }).id).toBe(raw.id)
  }
  expect(signNodeMigrationCommit({ preparation, authoritySk, ready: v.ready, now: v.now + 2 }).id).toBe(v.commit.id)
  expect(readNodeMigrationCommit(v.commit, v.now + 3600, node.authority)?.ready).toHaveLength(3)
  expect(nodeMigrationDigest(['02'.repeat(32), '01'.repeat(32), '01'.repeat(32)])).toBe(v.history.digest)
}, 20_000)
