# @forgesworn/fold-kit

Circle primitives for private Nostr groups that nobody operates: a room key
per epoch, sealed to each device that stays; link invitations as
capabilities; member removal by rekey; device credentials so a person
approves a device once and it signs from then on.

Fold-kit is extracted from [KithMoot](https://github.com/forgesworn/kithmoot)
so that other ForgeSworn clients can share one circle model. KithMoot's wire
format does not change: every derivation label and event shape moved
byte-identical from the pinned source commit and is pinned by known-answer
vectors (see EXTRACTION.md). Framework-free: owns no storage, UI, relay
defaults or identity keys, and no relay I/O of its own - callers inject a
transport.

**Status:** T1 extraction complete (see EXTRACTION.md). Not yet published to
npm under this API; pin an immutable Git commit until it is (see Install).
KithMoot itself has not cut over to this kit yet - it still carries its own
copy of these modules.

## Install

```bash
npm install @forgesworn/fold-kit
```

Not yet published to npm. Until it is, pin an immutable Git commit:

```json
{
  "dependencies": {
    "@forgesworn/fold-kit": "github:forgesworn/fold-kit#<commit>"
  }
}
```

### Peer dependencies

```json
{
  "peerDependencies": {
    "nostr-tools": ">=2.24.2 <3",
    "@noble/hashes": "^1.8.0",
    "@noble/curves": "^2.0.1"
  }
}
```

Peers, not dependencies, so a consumer such as KithMoot keeps a single copy
of `nostr-tools` (guarded by its own `overrides` and version-guard test) and
of the noble libraries, at the same versions KithMoot already pins.
`@noble/hashes` is pinned to its 1.x major only: its 2.x major changed its
`hkdf` signature to reject a string `info` argument (this kit's HKDF calls
pass strings) and its `exports` map no longer resolves the bare subpaths
this kit and KithMoot both import without a `.js` suffix, so 2.x cannot
satisfy this kit's imports as written.

ESM only (`"type": "module"`). Node.js `>=22.13`.

## Exports

Two entry points: `@forgesworn/fold-kit` (everything) and
`@forgesworn/fold-kit/lane` (just the lane helpers, for a consumer that only
wants to classify a relay as `public`/`sheltered`/`direct` without pulling in
the rest).

### Identity, verification, hex

- `hexEquals`, `normaliseHex` - constant-shape hex comparison and lower-casing
- `verifyEventUncached`, `boundedEventVerifier` - Nostr event signature checks
- `localIdentity`, `ParticipantIdentity`, `UnsignedEvent` - the signer seam
  every codec below is built on

### Wire kinds and types

- `KINDS` - the circle layer's kind numbers (`CREDENTIAL`, `CHAT`,
  `INVITATION_REQUEST`, `INVITATION_GRANT`, `INVITATION_RETIREMENT`,
  `GROUP_INVITATION`, `ROOM_REKEY`, `EPOCH_REQUEST`, `EPOCH_GRANT`) - a
  subset of KithMoot's full registry. `CHAT` (1460) is included because a
  downstream app's own board events are designed to share KithMoot's chat
  kind, so a relay cannot tell a board from a chat (see
  docs/extraction-plan-excerpt.md).
- `DeviceCredential`, `AccessTier`, `AgentRule`, `RoomPolicy`, `KindredProof` -
  the link-layer wire types
- `RelayTransport` - the transport seam (`publish`/`subscribe`/`close`) every
  codec below that talks to a relay takes as a dependency. This kit declares
  its own interface rather than importing KithMoot's relay pool, which has
  not moved here (see EXTRACTION.md).

### Rooms, credentials, access

- `generateRoomSecret`, `deriveRoom`, `encodeJoinUrl`, `decodeJoinUrl`,
  `parseRoomPolicy` - the legacy v1 join URL and room id/key derivation
- `createDeviceCredential`, `verifyDeviceCredential`,
  `PERSON_CREDENTIAL_MAX_SECONDS` - room-scope and person-scope device
  credentials. `createDeviceCredential` throws `RestampedCredentialExpiryError`
  for a person-scope credential a restamping signer would make unverifiable
  everywhere (see CHANGELOG.md) - catch it and retry with a shorter
  `expiresAt` margin
- `issueKindredProof`, `evaluateAccess` - kindred-tier admission
- `sanitiseDisplayName`, `MAX_DISPLAY_NAME_LENGTH` - defused display names
- `safeRelayUrls`, `safeIceUrls`, `assertNetworkHintBounds`, and the related
  `MAX_*` bounds - link envelope network hints

### Links and invitations

- `parseRoomLink`, `encodeRoomLink`, `RoomLink` - the v1/v2/v3 link envelope
- `createRoomInvitation`, `roomInvitation`, `deriveInvitationId`,
  `encodeInvitationRequest`, `decodeInvitationRequest`,
  `verifyInvitationDelegation`, `encodeInvitationGrant`,
  `decodeRoomAdmissionGrant`, `encodeInvitationRetirement`,
  `decodeInvitationRetirementNotice`, `hostRoomInvitation`,
  `requestRoomAdmission` - the v2 live rendezvous invitation, its delegation
  chain and retirement
- `encodePersistentInvitation`, `decodePersistentInvitation`,
  `requestPersistentRoomAdmission` - the v3 stored group invitation (1463).
  Pass `endsAt` (unix seconds, after `now` and at most 30 days on) for a
  conference room: the encrypted body carries `ends` and the event a NIP-40
  `expiration` tag, so relays drop it when the room ends; the decoder returns
  `endsAt` and refuses a tag that disagrees with the body
- `withExpiration`, `isRoomEnds`, `requireRoomEnds`, `MAX_ROOM_ENDS_SECONDS` -
  the conference-room expiration rule: add the end as an `expiration` tag,
  keep an earlier one, lower a later one. `encodeInvitationRetirement` takes
  `endsAt`, and the epoch encoders, `hostRoomEpoch` and `requestRoomEpoch`
  take `expiresAt`, to tag what they sign the same way

### Epochs (removal by rekey)

- `deriveEpoch`, `generateEpochSecret` - per-epoch id/key derivation
- `encodeRekeyEvent`, `peekRekeyEvent`, `decodeRekeyEvent` - the durable
  rekey notice (1462), sealed per remaining device
- `encodeEpochRequest`, `decodeEpochRequest`, `encodeEpochGrant`,
  `decodeEpochGrant`, `epochRequestAdmission`, `deriveEpochRequestKey` -
  catch-up for a device that missed a rekey
- `hostRoomEpoch`, `requestRoomEpoch`, `EpochRefusedError` - the live
  request/grant desk
- `canonicalAdmins`, `signAdmins`, `verifyAdmins` - the authority's signed
  admin list
- `canonicalChannels`, `signChannels`, `verifyChannels`, `CHANNEL_NAME`,
  `RESERVED_CHANNELS` - the authority's signed channel list

### Scoped labels and sub-key certificates (a consuming app's own keys)

- `deriveScoped` - derive an app-defined `{ id, key }` pair from an epoch key
  under an app's own labelled namespace (e.g. `myapp/v1/board/<id>/update`),
  so an app can ride the same epoch as the roster and the chat - and rotate
  on the same rekey - without ever deriving a key that could be mistaken for
  a KithMoot channel. Refuses this kit's own protocol namespace and any
  label outside `SCOPED_LABEL_PATTERN`.
- `createSubKeyCertificate`, `verifySubKeyCertificate`,
  `SUB_KEY_CERTIFICATE_SCOPE` - a small, locally-signed statement that a
  credentialled device minted a particular app-derived key (a `deriveScoped`
  output, typically) for a particular scoped id. Rides inside a signed
  message's ciphertext alongside the device credential it depends on; never
  published on its own, and never accepted by `verifyDeviceCredential` (its
  `scope: "sub"` is a value that function already refuses). Verification is
  strict and canonical: exactly four two-element tags in a fixed order,
  empty `content`, an `expiration` in canonical decimal form compared as the
  exact tag string (not numerically) against the device credential passed
  in - `verifySubKeyCertificate` reads that credential's own `device` and
  `expiration` tags itself, rather than trusting a caller to have copied
  them out correctly.

### Channel (main entry, and `deriveChannel` only)

- `deriveChannel`, `CHANNEL_ID_INFO`, `CHANNEL_KEY_INFO`,
  `MAX_CHANNEL_NAME_LENGTH` - a named channel's id/key, derived from the room
  key. `ChatLog` and the chat event codecs stay in KithMoot; only the
  derivation moved.

### Lane (`@forgesworn/fold-kit/lane`)

- `LANES`, `LANE_MEANING`, `LANE_LABEL`, `LANE_GLYPH`, `isLane`,
  `laneOfRelayUrl`, `laneOfRelays`, `weakestLane`, `isDowngrade` - classifies
  a relay as `public`, `sheltered` or `direct`

## How it relates to its siblings

- [`covey-kit`](https://github.com/forgesworn/covey-kit): circle state
  derived from a root, latest-wins configuration, per-recipient gift wraps.
- [`roost-kit`](https://github.com/forgesworn/roost-kit): transport for
  private circles (gift wrap, relay fan-out, offline outbox).
- `fold-kit`: symmetric epoch keys with a pinned authority, sealed rekeys and
  link invitations. Suited to high-rate encrypted streams such as chat and
  collaborative documents, where a wrap per recipient per message is too
  costly.

Nothing is shared in code between the three today: the key models are
incompatible (a static epoch secret with sealed rekeys here, versus a
deterministic reseed from a root in covey-kit), the trust models differ
(pinned authority here versus caller-enforced roles in covey-kit), and
covey-kit/roost-kit pin a different `nostr-tools` version than this kit and
KithMoot share.

## Development

```bash
npm install
npm run build       # compile TypeScript into dist/
npm test            # run the Vitest suite, including both vector files
npm run typecheck    # type-check src/ and test/ (matching KithMoot, vectors/ is not tsc-checked)
npm run vectors      # run only the vector-verification suites
npm run diff-source  # compare moved modules against the pinned source commit (needs FOLD_KIT_SOURCE_DIR)
npm run generate-fold # regenerate vectors/fold-vectors.json (needs a prior build)
npm run bundle-check # esbuild browser bundle check (needs a prior build)
npm run check        # typecheck + test + diff-source
```

There is no separate lint script.

## Licence

MIT
