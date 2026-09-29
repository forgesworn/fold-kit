// Freezes every `kithmoot/` string in this kit's `src/` - HKDF info strings,
// message domain prefixes and content-version markers - copied from
// KithMoot's `src/labels.test.ts` and cut down to the modules that moved to
// this kit (see EXTRACTION.md: "Every module that owns `kithmoot/` wire
// strings exports a frozen `*_LABELS` list; after cutover KithMoot's label
// test imports the kit's lists."). These are protocol names, not branding:
// every one must stay byte-identical to what KithMoot signs and encrypts
// under today.
//
// This test does not care which module a label lives in, only that the
// full set found by scanning `src/*.ts` (excluding `.test.ts` files and
// this file) exactly matches the frozen list below.
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ACCESS_LABELS } from './access.js'
import { CHANNEL_LABELS, CHANNEL_ID_INFO, CHANNEL_KEY_INFO } from './channel.js'
import { EPOCH_LABELS, EPOCH_ID_INFO, EPOCH_KEY_INFO } from './epoch.js'
import { EPOCH_INVITATION_LABELS } from './epoch-invitation.js'
import { INVITATION_LABELS } from './invitation.js'
import { PERSISTENT_INVITATION_LABELS } from './persistent-invitation.js'
import { ROOM_LABELS } from './room.js'

const here = dirname(fileURLToPath(import.meta.url))

/** Matches a `kithmoot/...` literal up to (but not including) the next
 *  character outside its alphabet - so a template literal's `${...}`
 *  interpolation is captured only up to its own fixed prefix, e.g.
 *  `` `kithmoot/v1/admins:${roomId}` `` yields `kithmoot/v1/admins:`. */
const LABEL_PATTERN = /kithmoot\/[A-Za-z0-9/_.:-]*/g

function findLabels(): Set<string> {
  const found = new Set<string>()
  for (const entry of readdirSync(here)) {
    if (!entry.endsWith('.ts') || entry.endsWith('.test.ts')) continue
    const text = readFileSync(join(here, entry), 'utf8')
    for (const match of text.matchAll(LABEL_PATTERN)) found.add(match[0])
  }
  return found
}

/**
 * The full, frozen set of `kithmoot/` wire-format strings this kit's `src/`
 * carries, as of the circle-kit extraction. This is a strict subset of
 * KithMoot's own frozen list (`kithmoot/src/labels.test.ts`): the labels
 * owned by modules that stayed in KithMoot (roster, signalling, pairing,
 * call bell, and so on) are not here.
 */
const FROZEN_LABELS: readonly string[] = [
  'kithmoot/v1/admins:',
  'kithmoot/v1/channel-id/',
  'kithmoot/v1/channel-key/',
  'kithmoot/v1/channels:',
  'kithmoot/v1/epoch-id',
  'kithmoot/v1/epoch-key',
  'kithmoot/v1/epoch-request-key',
  'kithmoot/v1/epoch-request:',
  'kithmoot/v1/kindred:',
  'kithmoot/v1/room-id',
  'kithmoot/v1/room-key',
  'kithmoot/v2/invitation-delegation:',
  'kithmoot/v2/invitation-id',
  'kithmoot/v2/invitation-request-key',
  'kithmoot/v3/group-invitation-key',
  'kithmoot/v4/group-invitation-key',
]

describe('kithmoot/ wire-format labels', () => {
  it('src/ carries exactly the frozen set of labels, no more and no fewer', () => {
    const found = [...findLabels()].sort()
    expect(found).toEqual([...FROZEN_LABELS].sort())
  })

  it('every label starts with a version segment, so a future unversioned string cannot slip in unnoticed', () => {
    for (const label of FROZEN_LABELS) {
      expect(label).toMatch(/^kithmoot\/v[0-9]+\//)
    }
  })

  it('the frozen list itself has no duplicates', () => {
    expect(new Set(FROZEN_LABELS).size).toBe(FROZEN_LABELS.length)
  })
})

// ===========================================================================
// Per-module: each label-bearing module exports its own frozen list
// (`ACCESS_LABELS`, `INVITATION_LABELS`, ...), and this checks each one
// against a scan of THAT module's own file, rather than scanning `src/*.ts`
// as a whole.
// ===========================================================================

const MODULE_LABEL_LISTS: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['access.ts', ACCESS_LABELS],
  ['channel.ts', CHANNEL_LABELS],
  ['epoch.ts', EPOCH_LABELS],
  ['epoch-invitation.ts', EPOCH_INVITATION_LABELS],
  ['invitation.ts', INVITATION_LABELS],
  ['persistent-invitation.ts', PERSISTENT_INVITATION_LABELS],
  ['room.ts', ROOM_LABELS],
]

function findLabelsInFile(file: string): string[] {
  const text = readFileSync(join(here, file), 'utf8')
  const found = new Set<string>()
  for (const match of text.matchAll(LABEL_PATTERN)) found.add(match[0])
  return [...found].sort()
}

describe('per-module label exports (checked against exported constants, not comment text)', () => {
  for (const [file, exported] of MODULE_LABEL_LISTS) {
    it(`${file}'s exported label list matches a fresh scan of ${file} alone`, () => {
      expect([...exported].sort()).toEqual(findLabelsInFile(file))
    })
  }

  it('the union of every module\'s own exported list is exactly the frozen, directory-wide set above', () => {
    const union = new Set<string>()
    for (const [, exported] of MODULE_LABEL_LISTS) for (const label of exported) union.add(label)
    expect([...union].sort()).toEqual([...FROZEN_LABELS].sort())
  })

  it('no label is claimed by more than one module\'s exported list, except the room id/key pair', () => {
    // 'kithmoot/v1/room-id' and 'kithmoot/v1/room-key' are the one
    // deliberate exception carried over from KithMoot's own label test:
    // `media-crypto.ts` (not moved here) derives its media key from the
    // same two HKDF info strings `room.ts`'s `deriveRoom` uses for the room
    // id/key themselves. Nothing in this kit re-declares them a second
    // time, so this exception is inherited rather than exercised here, but
    // it is kept so the two label tests stay easy to compare.
    const SHARED_EXCEPTIONS = new Set(['kithmoot/v1/room-id', 'kithmoot/v1/room-key'])
    const owners = new Map<string, string[]>()
    for (const [file, exported] of MODULE_LABEL_LISTS) {
      for (const label of exported) {
        const existing = owners.get(label) ?? []
        if (existing.length > 0 && !SHARED_EXCEPTIONS.has(label)) {
          expect.fail(`"${label}" is claimed by both ${existing.join(', ')} and ${file}`)
        }
        owners.set(label, [...existing, file])
      }
    }
  })
})

// ===========================================================================
// Composed labels: `deriveEpoch`'s per-epoch info strings and
// `deriveChannel`'s per-channel info strings are built by string
// concatenation at their call site, so neither the whole-file scan above nor
// a module's own frozen list (which records only the fixed PREFIX) pins the
// exact bytes a real epoch or channel derivation signs/encrypts under.
// ===========================================================================

describe('composed labels (info strings built by concatenation, not a fixed literal)', () => {
  it('deriveEpoch composes EPOCH_ID_INFO/EPOCH_KEY_INFO with "/" + the epoch number', () => {
    expect(`${EPOCH_ID_INFO}/1`).toBe('kithmoot/v1/epoch-id/1')
    expect(`${EPOCH_KEY_INFO}/1`).toBe('kithmoot/v1/epoch-key/1')
    expect(`${EPOCH_ID_INFO}/2`).toBe('kithmoot/v1/epoch-id/2')
    expect(`${EPOCH_ID_INFO}/1`).not.toBe(`${EPOCH_ID_INFO}/2`)
  })

  it('deriveChannel composes CHANNEL_ID_INFO/CHANNEL_KEY_INFO directly with the channel name (no separator)', () => {
    expect(CHANNEL_ID_INFO + 'planning').toBe('kithmoot/v1/channel-id/planning')
    expect(CHANNEL_KEY_INFO + 'planning').toBe('kithmoot/v1/channel-key/planning')
    expect(CHANNEL_ID_INFO + 'planning').not.toBe(CHANNEL_ID_INFO + 'social')
  })
})
