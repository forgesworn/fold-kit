import { readFileSync } from 'node:fs'
import { expect, it } from 'vitest'
import { encodeNodeMigrationFrames, NodeMigrationFrameReceiver, readNodeMigrationFrame } from './node-migration.js'
const v = JSON.parse(readFileSync(new URL('../vectors/node-migration-vectors.json', import.meta.url), 'utf8'))
const source = v.preparation.pubkey
it('carries a complete three-client decision under the 2000-character encrypted control limit', () => {
  const frames = encodeNodeMigrationFrames(v.commit), receiver = new NodeMigrationFrameReceiver()
  expect(frames).toEqual(v.frames)
  expect(frames.length).toBeGreaterThan(1)
  expect(frames.every(f => JSON.stringify(f).length <= 2000)).toBe(true)
  const complete = [...frames].reverse().flatMap(f => { const event = receiver.push(f, source, v.now); return event ? [event] : [] })
  expect(complete).toEqual([v.commit])
  expect(frames.every(f => receiver.push(f, source, v.now) === null)).toBe(true)
})
it('does not combine senders, accept truncation, changed bytes or invalid signature', () => {
  const frames = encodeNodeMigrationFrames(v.commit), receiver = new NodeMigrationFrameReceiver()
  for (const [i, frame] of frames.entries()) expect(receiver.push(frame, i === 0 ? '00'.repeat(32) : source, v.now)).toBeNull()
  receiver.clear()
  for (const frame of frames.slice(1)) expect(receiver.push(frame, source, v.now)).toBeNull()
  expect(receiver.push({ ...frames[0], data: frames[0]!.data.slice(0, -1) + (frames[0]!.data.endsWith('a') ? 'b' : 'a') }, source, v.now)).toBeNull()
  expect(() => encodeNodeMigrationFrames({ ...v.commit, sig: '00'.repeat(64) })).toThrow()
  expect(readNodeMigrationFrame({ ...frames[0], total: 10_000_000 })).toBeNull()
  expect(readNodeMigrationFrame({ ...frames[0], unexpected: true })).toBeNull()
})
it('bounds pending assemblies, expires partial copies and rejects conflicting duplicate parts', () => {
  const frames = encodeNodeMigrationFrames(v.commit), receiver = new NodeMigrationFrameReceiver()
  receiver.push(frames[0], source, v.now)
  for (const frame of frames.slice(1)) expect(receiver.push(frame, source, v.now + 300)).toBeNull()
  receiver.clear()
  receiver.push(frames[0], source, v.now)
  receiver.push({ ...frames[0], total: frames[0]!.total + 1 }, source, v.now)
  for (const frame of frames.slice(1)) expect(receiver.push(frame, source, v.now)).toBeNull()
  receiver.clear()
  for (let i = 0; i < 100; i++) receiver.push({ ...frames[0], id: i.toString(16).padStart(64, '0') }, source, v.now)
  const completed = frames.flatMap(f => { const e = receiver.push(f, source, v.now + 300); return e ? [e] : [] })
  expect(completed).toEqual([v.commit])
})
