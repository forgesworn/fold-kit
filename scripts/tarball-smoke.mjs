#!/usr/bin/env node
// Real-tarball consumer smoke test: `npm pack`, install the tarball into a
// scratch directory alongside the peer dependencies, and import every
// export from both entry points. See EXTRACTION.md for the extraction this
// check belongs to.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const root = process.cwd()
const pkg = JSON.parse(execFileSync('node', ['-e', 'console.log(JSON.stringify(require("./package.json")))'], { cwd: root, encoding: 'utf8' }))

console.log('tarball-smoke: npm pack')
const before = new Set(readdirSync(root).filter((f) => f.endsWith('.tgz')))
execFileSync('npm', ['pack'], { cwd: root, stdio: 'inherit' })
const after = readdirSync(root).filter((f) => f.endsWith('.tgz') && !before.has(f))
if (after.length !== 1) throw new Error(`expected exactly one new .tgz, found ${after.length}`)
const tarball = join(root, after[0])

const scratch = mkdtempSync(join(tmpdir(), 'fold-kit-smoke-'))
try {
  console.log(`tarball-smoke: installing into ${scratch}`)
  writeFileSync(
    join(scratch, 'package.json'),
    JSON.stringify(
      {
        name: 'fold-kit-smoke',
        private: true,
        type: 'module',
        dependencies: {
          '@forgesworn/fold-kit': tarball,
          'nostr-tools': pkg.devDependencies['nostr-tools'],
          '@noble/hashes': pkg.devDependencies['@noble/hashes'],
          '@noble/curves': pkg.devDependencies['@noble/curves'],
        },
      },
      null,
      2,
    ),
  )
  execFileSync('npm', ['install', '--no-audit', '--no-fund'], { cwd: scratch, stdio: 'inherit' })

  writeFileSync(
    join(scratch, 'smoke.mjs'),
    `
import * as main from '@forgesworn/fold-kit'
import * as lane from '@forgesworn/fold-kit/lane'

const expectedMain = ${JSON.stringify([
      'hexEquals', 'normaliseHex', 'verifyEventUncached', 'boundedEventVerifier', 'localIdentity',
      'KINDS', 'createDeviceCredential', 'verifyDeviceCredential', 'PERSON_CREDENTIAL_MAX_SECONDS', 'RestampedCredentialExpiryError',
      'generateRoomSecret', 'deriveRoom', 'encodeJoinUrl', 'decodeJoinUrl', 'parseRoomPolicy', 'ROOM_LABELS',
      'MAX_RELAY_HINTS', 'MAX_ICE_HINTS', 'MAX_NETWORK_HINT_LENGTH', 'isSafeRelayUrl', 'safeRelayUrls',
      'isSafeIceUrl', 'safeIceUrls', 'assertNetworkHintBounds', 'sanitiseDisplayName', 'MAX_DISPLAY_NAME_LENGTH',
      'issueKindredProof', 'evaluateAccess', 'ACCESS_LABELS',
      'INVITATION_DELEGATION_TTL_SECONDS', 'MAX_INVITATION_DELEGATION_DEPTH', 'createRoomInvitation', 'roomInvitation',
      'deriveInvitationId', 'encodeInvitationRequest', 'decodeInvitationRequest', 'verifyInvitationDelegation',
      'encodeInvitationGrant', 'decodeRoomAdmissionGrant', 'decodeInvitationGrant', 'ROOM_ENDED_MESSAGE',
      'encodeInvitationRetirement', 'decodeInvitationRetirement', 'decodeInvitationRetirementNotice', 'retirementError',
      'hostRoomInvitation', 'requestRoomAdmissionCapability', 'requestRoomAdmission', 'INVITATION_LABELS',
      'encodePersistentInvitation', 'decodePersistentInvitation', 'requestPersistentRoomAdmission', 'PERSISTENT_INVITATION_LABELS',
      'withExpiration', 'isRoomEnds', 'requireRoomEnds', 'MAX_ROOM_ENDS_SECONDS',
      'isInvitationRelays', 'requireInvitationRelays', 'MAX_INVITATION_RELAYS',
      'MAX_ROOM_LINK_FRAGMENT_LENGTH', 'parseRoomLink', 'encodeRoomLink',
      'EPOCH_ID_INFO', 'EPOCH_KEY_INFO', 'MAX_EPOCH', 'EPOCH_REQUEST_KEY_INFO', 'generateEpochSecret', 'deriveEpoch',
      'encodeRekeyEvent', 'peekRekeyEvent', 'decodeRekeyEvent', 'deriveEpochRequestKey', 'epochRequestAdmission',
      'encodeEpochRequest', 'decodeEpochRequest', 'encodeEpochGrant', 'decodeEpochGrant', 'hostRoomEpoch',
      'EpochRefusedError', 'requestRoomEpoch', 'canonicalAdmins', 'CHANNEL_NAME', 'RESERVED_CHANNELS',
      'canonicalChannels', 'signChannels', 'verifyChannels', 'signAdmins', 'verifyAdmins', 'EPOCH_LABELS',
      'deriveChannel', 'CHANNEL_ID_INFO', 'CHANNEL_KEY_INFO', 'MAX_CHANNEL_NAME_LENGTH', 'CHANNEL_LABELS',
      'deriveScoped', 'SCOPED_LABEL_PATTERN',
      'createSubKeyCertificate', 'verifySubKeyCertificate', 'SUB_KEY_CERTIFICATE_SCOPE',
      'LANES', 'LANE_MEANING', 'LANE_LABEL', 'LANE_GLYPH', 'isLane', 'laneOfRelayUrl', 'laneOfRelays', 'weakestLane', 'isDowngrade',
    ])}
const expectedLane = ${JSON.stringify(['LANES', 'LANE_MEANING', 'LANE_LABEL', 'LANE_GLYPH', 'isLane', 'laneOfRelayUrl', 'laneOfRelays', 'weakestLane', 'isDowngrade'])}

let missing = []
for (const name of expectedMain) if (!(name in main)) missing.push('main:' + name)
for (const name of expectedLane) if (!(name in lane)) missing.push('lane:' + name)
if (missing.length > 0) {
  console.error('tarball-smoke: missing exports: ' + missing.join(', '))
  process.exit(1)
}

// One real call through each entry point, not just a presence check.
const room = main.deriveRoom(new Uint8Array(32).fill(7))
if (!/^[0-9a-f]{64}$/.test(room.roomId)) throw new Error('deriveRoom did not return a hex room id')
if (lane.laneOfRelayUrl('wss://relay.example') !== 'public') throw new Error('laneOfRelayUrl misbehaved')
const scoped = main.deriveScoped({ epoch: 0, id: room.roomId, key: room.roomKey }, 'smoke/v1/x')
if (!/^[0-9a-f]{64}$/.test(scoped.id)) throw new Error('deriveScoped did not return a hex id')

console.log('tarball-smoke: all ' + expectedMain.length + ' main exports and ' + expectedLane.length + ' lane exports present and callable')
`,
  )
  execFileSync('node', ['smoke.mjs'], { cwd: scratch, stdio: 'inherit' })
  console.log('tarball-smoke: ok')
} finally {
  rmSync(scratch, { recursive: true, force: true })
  rmSync(tarball, { force: true })
}
