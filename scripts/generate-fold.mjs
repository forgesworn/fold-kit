#!/usr/bin/env node
// Known-answer vectors for this kit's own new T3.1/T3.3 work: `deriveScoped`
// (scoped.ts) and the sub-key certificate (sub-cert.ts).
//
// Built the same way `kithmoot-vectors.json`/`circle-vectors.json` are: real
// functions, fixed labelled inputs, deterministic signing via
// `vectors/lib/determinism.mjs`. Unlike those two files (copied byte-for-byte
// from the pinned KithMoot commit, per EXTRACTION.md), this file and its
// generator belong to this kit alone - there is no upstream KithMoot copy to
// diff against, so `scripts/diff-source.mjs` does not touch it.
//
// Every negative certificate vector is VALIDLY SIGNED (re-signed under its
// mutated tags/content with a fresh, deterministic signature) rather than
// reusing the positive certificate's original signature over different
// bytes: `verifySubKeyCertificate`'s structural checks run before the
// signature check, so a stale signature would refuse for the right reason
// by accident even if the structural check under test were broken. A
// validly signed negative proves the specific check is what refuses it.
//
// Run after `npm run build` (imports the built package, matching
// scripts/bundle-check.mjs and scripts/tarball-smoke.mjs): `npm run
// generate-fold`. Verified independently, against `src/` directly (not
// dist/), by `vectors/verify-fold.test.ts`.
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { getPublicKey } from 'nostr-tools/pure'
import { seed32, deriveSecretKey, finalizeDeterministic } from './../vectors/lib/determinism.mjs'
import { deriveScoped, createSubKeyCertificate, createDeviceCredential, verifyDeviceCredential } from '../dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const outPath = join(here, '..', 'vectors', 'fold-vectors.json')

// --- Fixed inputs ----------------------------------------------------------

const BOARD_1 = '11111111-1111-4111-8111-111111111111'
const BOARD_2 = '22222222-2222-4222-8222-222222222222'
const SCOPED_NAMES = ['update', 'pointer', 'record', 'presence', 'snapshot', 'signer', 'uploader']

const EPOCH_0_KEY = seed32('fold/epoch-0-key')
const EPOCH_3_KEY = seed32('fold/epoch-3-key')

const PARTICIPANT_SK = deriveSecretKey('fold/participant-a')
const DEVICE_SK = deriveSecretKey('fold/device-a')
const DEVICE = getPublicKey(DEVICE_SK)
const IMPOSTOR_DEVICE_SK = deriveSecretKey('fold/device-impostor')
const IMPOSTOR_DEVICE = getPublicKey(IMPOSTOR_DEVICE_SK)
const SUB_KEY_SK = deriveSecretKey('fold/sub-key-a')
const SUB_KEY = getPublicKey(SUB_KEY_SK)
const OTHER_SUB_KEY_SK = deriveSecretKey('fold/sub-key-b')
const OTHER_SUB_KEY = getPublicKey(OTHER_SUB_KEY_SK)

const CRED_AUX_RAND = seed32('fold/cred-aux-rand')
const IMPOSTOR_CRED_AUX_RAND = seed32('fold/impostor-cred-aux-rand')
const CERT_AUX_RAND = seed32('fold/cert-aux-rand')

/** A deterministic `ParticipantIdentity`/device signer: fixed aux-rand in
 *  place of the random default, exactly as credential.ts's own vectors do. */
function deterministicIdentity(secretKey, auxRand) {
  return {
    pubkey: getPublicKey(secretKey),
    async signEvent(unsigned) {
      return finalizeDeterministic(unsigned, secretKey, auxRand)
    },
  }
}

function plain(event) {
  const { id, pubkey, created_at, kind, tags, content, sig } = event
  return { id, pubkey, created_at, kind, tags, content, sig }
}

/** Re-sign an arbitrary (tags, content, created_at) triple as a real,
 *  validly signed kind-20460 event under `secretKey` - used to build every
 *  negative certificate vector so each one fails for exactly the reason
 *  under test, never for a stale signature over different bytes. */
function resign(secretKey, auxRand, { tags, content = '', created_at = NOW }) {
  return finalizeDeterministic({ kind: 20460, created_at, tags, content }, secretKey, auxRand)
}

function refused(fn) {
  try {
    fn()
    return { threw: false }
  } catch (err) {
    return { threw: true, message: err instanceof Error ? err.message : String(err) }
  }
}

const NOW = 1_800_000_000

// --- deriveScoped (T3.1) ----------------------------------------------------

const scopedPositive = []
for (const boardId of [BOARD_1, BOARD_2]) {
  for (const epoch of [{ n: 0, key: EPOCH_0_KEY }, { n: 3, key: EPOCH_3_KEY }]) {
    for (const name of SCOPED_NAMES) {
      const label = `example/v1/board/${boardId}/${name}`
      const scoped = deriveScoped({ epoch: epoch.n, id: 'unused-in-deriveScoped', key: epoch.key }, label)
      scopedPositive.push({
        boardId,
        epoch: epoch.n,
        name,
        label,
        output: { id: scoped.id, keyHex: Buffer.from(scoped.key).toString('hex') },
      })
    }
  }
}

const scopedRefusals = [
  {
    name: 'kithmoot-prefix',
    label: 'kithmoot/v1/epoch-id',
    result: refused(() => deriveScoped({ epoch: 0, id: 'x', key: EPOCH_0_KEY }, 'kithmoot/v1/epoch-id')),
  },
  {
    name: 'bad-label-no-version-segment',
    label: `example/board/${BOARD_1}/update`,
    result: refused(() => deriveScoped({ epoch: 0, id: 'x', key: EPOCH_0_KEY }, `example/board/${BOARD_1}/update`)),
  },
  {
    name: 'bad-label-uppercase-namespace',
    label: `Example/v1/board/${BOARD_1}/update`,
    result: refused(() => deriveScoped({ epoch: 0, id: 'x', key: EPOCH_0_KEY }, `Example/v1/board/${BOARD_1}/update`)),
  },
  {
    name: 'bad-board-id-embedded-space',
    label: 'example/v1/board/not a valid uuid/update',
    result: refused(() => deriveScoped({ epoch: 0, id: 'x', key: EPOCH_0_KEY }, 'example/v1/board/not a valid uuid/update')),
  },
  {
    name: 'namespace-over-64-bytes',
    label: `${'a'.repeat(65)}/v1/x`,
    result: refused(() => deriveScoped({ epoch: 0, id: 'x', key: EPOCH_0_KEY }, `${'a'.repeat(65)}/v1/x`)),
  },
  {
    name: 'namespace-exactly-64-bytes-accepted',
    label: `${'a'.repeat(64)}/v1/x`,
    result: refused(() => {
      const out = deriveScoped({ epoch: 0, id: 'x', key: EPOCH_0_KEY }, `${'a'.repeat(64)}/v1/x`)
      if (!out.id) throw new Error('unreachable')
    }),
  },
  {
    name: 'version-over-9-digits',
    label: `example/v${'9'.repeat(10)}/x`,
    result: refused(() => deriveScoped({ epoch: 0, id: 'x', key: EPOCH_0_KEY }, `example/v${'9'.repeat(10)}/x`)),
  },
]

// --- Sub-key certificate (T3.3) ---------------------------------------------

const signerId = deriveScoped({ epoch: 3, id: 'x', key: EPOCH_3_KEY }, `example/v1/board/${BOARD_1}/signer`).id
const otherSignerId = deriveScoped({ epoch: 3, id: 'x', key: EPOCH_3_KEY }, `example/v1/board/${BOARD_2}/signer`).id
const CERT_EXPIRES_AT = NOW + 3600

// The device credential the certificate depends on: DEVICE is the
// credentialled device (person-scope, but sub-cert verification does not
// care which form - it only reads `device` and `expiration`).
const credential = await createDeviceCredential({
  identity: deterministicIdentity(PARTICIPANT_SK, CRED_AUX_RAND),
  devicePubkey: DEVICE,
  scope: 'person',
  expiresAt: CERT_EXPIRES_AT,
  now: () => NOW,
})
// A second, unrelated credential (different device) for the wrong-device negative.
const impostorCredential = await createDeviceCredential({
  identity: deterministicIdentity(PARTICIPANT_SK, IMPOSTOR_CRED_AUX_RAND),
  devicePubkey: IMPOSTOR_DEVICE,
  scope: 'person',
  expiresAt: CERT_EXPIRES_AT,
  now: () => NOW,
})

const subCertPositiveEvent = await createSubKeyCertificate({
  identity: deterministicIdentity(DEVICE_SK, CERT_AUX_RAND),
  signerId,
  subKeyPubkey: SUB_KEY,
  expiresAt: CERT_EXPIRES_AT,
  now: () => NOW,
})

const goodTags = subCertPositiveEvent.tags

const subKeyCertificate = {
  input: { signerId, device: DEVICE, subKeyPubkey: SUB_KEY, expiresAt: CERT_EXPIRES_AT, now: NOW },
  credential: plain(credential),
  impostorCredential: plain(impostorCredential),
  output: { event: plain(subCertPositiveEvent) },
  verify: {
    positive: { opts: { signerId, subKeyPubkey: SUB_KEY, now: NOW } }, // `credential` supplied by the test from `credential` above
  },
  refusals: {
    // Structural, re-signed negatives.
    wrongOrder: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[1], goodTags[0], goodTags[2], goodTags[3]] })),
    },
    renamedDTag: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [['x', signerId], goodTags[1], goodTags[2], goodTags[3]] })),
    },
    renamedExpirationTag: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], ['x', goodTags[2][1]], goodTags[3]] })),
    },
    renamedDeviceTag: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], ['x', goodTags[1][1]], goodTags[2], goodTags[3]] })),
    },
    renamedScopeTag: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], goodTags[2], ['x', goodTags[3][1]]] })),
    },
    wrongScope: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], goodTags[2], ['scope', 'person']] })),
    },
    tagMissing: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], goodTags[2]] })),
    },
    tagExtra: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], goodTags[2], goodTags[3], ['extra', 'x']] })),
    },
    tagElementExtra: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [[...goodTags[0], 'z'], goodTags[1], goodTags[2], goodTags[3]] })),
    },
    nonEmptyContent: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: goodTags, content: 'hello' })),
    },
    expirationLeadingZero: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], ['expiration', '0' + String(CERT_EXPIRES_AT)], goodTags[3]] })),
    },
    expirationHexPrefix: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], ['expiration', '0x' + CERT_EXPIRES_AT.toString(16)], goodTags[3]] })),
    },
    expirationFraction: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], ['expiration', String(CERT_EXPIRES_AT) + '.0'], goodTags[3]] })),
    },
    expirationWhitespace: {
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], ['expiration', ' ' + String(CERT_EXPIRES_AT)], goodTags[3]] })),
    },
    expirationUnequalToCredential: {
      // Canonical decimal, but a different (later) number than the credential's own expiration tag.
      event: plain(resign(DEVICE_SK, CERT_AUX_RAND, { tags: [goodTags[0], goodTags[1], ['expiration', String(CERT_EXPIRES_AT + 1)], goodTags[3]] })),
    },
    // Verify-time parameter negatives (no re-sign needed: the certificate is
    // the valid positive one; only the caller's expectation differs).
    expired: { now: CERT_EXPIRES_AT + 1 },
    wrongSigner: { signerId: otherSignerId },
    wrongSubKeyPubkey: { subKeyPubkey: OTHER_SUB_KEY },
    wrongDevice: { useImpostorCredential: true },
  },
}

// verifyDeviceCredential refuses a sub-key certificate outright (scope
// "sub" is not one it recognises) - proving the two forms can never be
// confused, without any change to credential.ts.
const subCertAsDeviceCredential = {
  asIdentity: verifyDeviceCredential(subCertPositiveEvent, { identity: DEVICE, now: NOW }),
  asRoomAcceptPerson: verifyDeviceCredential(subCertPositiveEvent, { roomId: signerId, now: NOW, acceptPerson: true }),
}

// --- Independent recompute check data ---------------------------------------
// (the actual recompute is done in vectors/verify-fold.test.ts using
// @noble/hashes directly, not deriveScoped - this just records which epoch
// key each positive vector used, by epoch number, so the test does not need
// to re-derive EPOCH_0_KEY/EPOCH_3_KEY from anything other than the same
// fixed labels this generator used.)
const epochKeyLabels = { 0: 'fold/epoch-0-key', 3: 'fold/epoch-3-key' }

// --- Write -------------------------------------------------------------------

const doc = {
  protocolVersion: 2,
  generatedBy: 'scripts/generate-fold.mjs',
  groups: {
    scoped: { positive: scopedPositive, refusals: scopedRefusals, epochKeyLabels },
    subKeyCertificate: subKeyCertificate,
    subCertAsDeviceCredential,
  },
}

writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n')
console.log(`generate-fold: wrote ${outPath}`)
