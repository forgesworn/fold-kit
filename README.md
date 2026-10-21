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

**Status:** Version 0.14.0 on `main`. Published on npm as
`@forgesworn/fold-kit`, but `main` can run ahead of the npm `latest` release, so
compare `npm view @forgesworn/fold-kit version` with this repository's
`package.json` before relying on an API listed here. KithMoot has cut over to
this kit and pins an exact npm version; its moved files are re-export shims
(see EXTRACTION.md).

## Install

```bash
npm install @forgesworn/fold-kit
```

To use a change that has not been released, pin an immutable Git commit (a full
SHA, for example from `git ls-remote https://github.com/forgesworn/fold-kit main`).
The package's `prepare` script builds `dist/` on install:

```bash
npm install "github:forgesworn/fold-kit#<commit>"
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

Install the peers yourself, keeping `@noble/hashes` on 1.x:

```bash
npm install "nostr-tools@>=2.24.2 <3" "@noble/hashes@^1.8.0" "@noble/curves@^2.0.1"
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

## Quick start

Derive a room, then publish and load a stored group invitation through a
`RelayTransport` you supply (this one is an in-memory stub; a real transport
talks to relays and applies the filters):

```ts
import {
  generateRoomSecret,
  deriveRoom,
  deriveEpoch,
  localIdentity,
  createRoomInvitation,
  encodePersistentInvitation,
  requestPersistentRoomAdmission,
  type RelayTransport,
} from '@forgesworn/fold-kit'
import { generateSecretKey, type Event } from 'nostr-tools/pure'

// The person: a local signer. An external one (NIP-07, NIP-46) fits the same seam.
const me = localIdentity(generateSecretKey())

// The room: one secret opens epoch 0; later epochs come from rekeys.
const roomSecret = generateRoomSecret()
const { roomId, roomKey } = deriveRoom(roomSecret)
const epoch0 = deriveEpoch({ epoch: 0, secret: roomSecret }) // { epoch: 0, id: roomId, key: roomKey }

// A RelayTransport stub: stores events, replays them on subscribe, then signals EOSE.
const stored: Event[] = []
const transport: RelayTransport = {
  async publish(event) { stored.push(event) },
  subscribe(_filters, onEvent, onEose) {
    queueMicrotask(() => { for (const event of stored) onEvent(event); onEose?.() })
    return () => {}
  },
  close() {},
}

// Invitation flow (v3 stored group invitation): the inviter publishes once, and a
// guest holding the link loads it from the relays with no responder online.
const { invitation, inviterSk } = createRoomInvitation(true)
await transport.publish(encodePersistentInvitation({
  invitation, inviterSk, roomSecret, now: Math.floor(Date.now() / 1000),
}))
const admission = await requestPersistentRoomAdmission({ transport, invitation })
// admission.secret is the room secret: deriveRoom(admission.secret).roomId === roomId
```

Invitation versions: v1 (`encodeJoinUrl`, the room secret in the link) is
legacy, and new links go through `createRoomInvitation`. Use
`createRoomInvitation()` for the v2 live rendezvous, which needs a responder
online (`hostRoomInvitation` answers, `requestRoomAdmissionCapability` joins),
or `createRoomInvitation(true)` for the v3 stored group invitation above, which
needs none.

## Exports

Four entry points: `@forgesworn/fold-kit` (circle primitives),
`@forgesworn/fold-kit/lane` (just the lane helpers, for a consumer that only
wants to classify a relay as `public`/`sheltered`/`direct` without pulling in
the rest), `@forgesworn/fold-kit/mls-admission` (opt-in v4 evidence codec), and
`@forgesworn/fold-kit/persistent-invitation-evidence` (bounded stored invitation
observation and independent revalidation).

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

`hostRoomInvitation` distinguishes approval from grant publication. Its
`onGrantPublished(request)` and legacy `onAdmitted(device)` callbacks run only
after the injected transport acknowledges the grant's publication.
`onGrantFailed(request, error)` reports a rejected or throwing publication,
or approval of a request which has expired;
neither success callback runs for that failure. Closing or retiring the host
suppresses callbacks from outstanding sends. Publication acknowledgement does
not prove that a guest received the grant or joined; the guest validates its
grant independently. Observer exceptions do not change the publish outcome. Fresh retries of the same
signed request resend the exact cached grant after the configured quiet delay;
overlapping approval, wait and publication work is coalesced. Approval and
success callbacks each occur at most once per request. Failed sends may recover
on a later retry. The host retains up to 256 live decisions, including declines;
at capacity it refuses new work until settled requests expire. Close, retirement,
request freshness and responder authority still gate every send.

For a device that answers automatically, `grantDelayMs: [min, max]` waits a
random time before each grant, and `coordinate: true` lets several delegated
devices share one link: each waits (default 500 to 2000 ms) and stands down,
at most once per request, if another responder's grant to the same
requester appears. Both are off by default, and the wire format is
unchanged. See `docs/quiet-replies.md`.

An invitation request's `participant` is an unverified account claim.
Automatic admission of a previously invited account must use
`verifiedParticipant`, which is present only after a fresh signature check of
an account proof bound to this invitation, ephemeral request device and request
timestamp. `encodeInvitationAccountProof` creates that proof through the
supplied matching `ParticipantIdentity`. It grants no room access itself and
stays inside the bearer-encrypted request, rather than being published as a
public account event. Invalid or missing proofs leave a request unverified;
hosts can still make an explicit decision for anonymous and older clients.

Pass `identity` to `requestRoomAdmissionCapability` (or `requestRoomAdmission`,
its secret-only wrapper) to create the proof automatically. If `participant` is also supplied, it must
match the signer; a signer failure rejects the request without falling back to
another identity. `signal` cancels signing or waiting. Signing and relay waiting
share one deadline, capped at the request's 90-second freshness window, and
late signatures or grants cannot revive a cancelled, expired or retired request.
Retrying publication uses the same signed request. A fresh human retry starts a
new exchange. The helper copies a supplied `requesterSk` before signing and
erases only its owned copy on settlement. Hosts recheck freshness when a human
decision completes, so approval cannot extend an expired request's authority.

- `parseRoomLink`, `encodeRoomLink`, `RoomLink` - the v1/v2/v3 link envelope
- `createRoomInvitation`, `roomInvitation`, `deriveInvitationId`,
  `encodeInvitationAccountProof`, `encodeInvitationRequest`, `decodeInvitationRequest`,
  `verifyInvitationDelegation`, `encodeInvitationGrant`,
  `decodeRoomAdmissionGrant`, `encodeInvitationRetirement`,
  `decodeInvitationRetirementNotice`, `hostRoomInvitation`,
  `requestRoomAdmissionCapability`, `requestRoomAdmission` - the v2 live rendezvous invitation, its delegation
  chain and retirement
- `encodePersistentInvitation`, `decodePersistentInvitation`,
  `requestPersistentRoomAdmission` - the v3 stored group invitation (1463).
  Pass `endsAt` (unix seconds, after `now` and at most 30 days on) for a
  conference room: the encrypted body carries `ends` and the event a NIP-40
  `expiration` tag, so relays drop it when the room ends; the decoder returns
  `endsAt` and refuses a tag that disagrees with the body
- From `@forgesworn/fold-kit/persistent-invitation-evidence`,
  `requestPersistentRoomAdmissionEvidence` and
  `revalidatePersistentInvitationEvidence` retain and independently recheck a
  bounded set of canonical signed invitation/retirement carriers, with exact
  invitation and contributing event IDs. The additive evidence path holds on
  conflicting newest equal-time relay lists; the legacy request is unchanged.
  EOSE is local observation metadata, never proof of current membership or
  global non-retirement. Persist the evidence in protected custody before
  using its decoded fields. See [the evidence contract](docs/persistent-invitation-evidence.md).
- The same optional entry exports `revalidatePersistentInvitationSource` for
  an actual encoder event or its exact canonical retained string. It requires
  the invitation capability and exact room-root pin, independently verifies
  the signature and supported body/tags, and returns one canonical carrier
  plus owned decoded fields. This single source has no EOSE, publication,
  latest-selection or current-membership claim. Creators retain that event
  and their publication intent before opening a pool, then retry the same
  bytes; protected persistence and fresh effect guards belong to the client.
- Room relays: pass `relays` (one to eight distinct safe relay URLs in
  canonical `normalizeURL` form, e.g. `wss://relay.example.com/`) and the
  encrypted body carries them after `ends`. Every member's pool includes
  them, so members never land on disjoint relays. The decoder returns
  `relays` and refuses the whole envelope on a malformed list;
  `requestPersistentRoomAdmission` keeps the relays of the newest signed
  copy that names any. `isInvitationRelays`, `requireInvitationRelays` and
  `MAX_INVITATION_RELAYS` are the rule
- Room storage nodes: pass `storage` (zero to eight canonical node base URLs
  on distinct hosts, e.g. `https://grove.example.net` or
  `http://127.0.0.1:8080`) and the encrypted body carries them last, after
  `relays`, so a room that keeps its files on its own computers says where.
  An entry is only a base URL; the grammar (no trailing slash, no default
  port, `http` only on this machine or an onion address) is in
  `src/invitation-storage.ts` and pinned by vectors, not by what a URL parser
  prints. `[]` says the authority withdrew every node; a body with no
  `storage` says nothing about nodes, and is byte-identical to 0.13.0's. The
  decoder returns `storage` and `storageAt` (the `created_at` of the copy
  whose list stood) and refuses the whole envelope on a malformed list.
  `requestPersistentRoomAdmission` and the strict evidence path keep the list
  of the newest signed copy that names any, independently of the relays; the
  strict path holds a same-second disagreement as `conflicting-storage`.
  `storageNodeFromBase(text)` canonicalises an operator's URL and gives its
  `server`; `isStorageNodeBase`, `isInvitationStorage`,
  `requireInvitationStorage`, `MAX_INVITATION_STORAGE_NODES` and
  `MAX_STORAGE_NODE_URL_LENGTH` are the rule. Vectors:
  `vectors/storage-vectors.json`
- Self-destructing rooms (`docs/room-destruct.md`): pass `destruct: true`
  and the encrypted body carries it after `ends` (no end needed: the room
  then self-destructs when its authority closes it). The decoder returns
  `destruct: true` and refuses the envelope on any other value;
  `requestPersistentRoomAdmission` keeps it if any signed copy says it.
  `encodeInvitationRetirement({ ended: true, destruct: true })` and
  `encodeRekeyEvent({ closed: true, destruct: true })` carry it when the
  room ends early, read back by `decodeInvitationRetirementNotice`,
  `RekeyNotice.destruct` and `RekeyEvidence.destruct`. Vectors:
  `vectors/destruct-vectors.json`
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
- Quiet replies (`docs/quiet-replies.md`): `hostRoomEpoch` waits a random
  `replyDelayMs` (default `[500, 2000]`) before any answer, sends a
  participant a `removed` or `closed` refusal once per `refuseAgainAfter`
  (default 3600 s) and `unknown` once per `reportUnknownEvery` (60 s), and
  caps refusals at `maxRefusalsPerMinute` (20). Grants are never limited.
  `RefusalLimiter`, `replyDelay` and the `DEFAULT_REPLY_DELAY_MS`,
  `REFUSE_AGAIN_AFTER_SECONDS`, `MAX_REFUSALS_PER_MINUTE` and
  `REFUSAL_LIMITER_CAPACITY` constants are exported
- Member epoch catch-up (`docs/member-epoch-catch-up.md`): any current
  member can bring an admitted, non-removed device up to date when the
  authority is offline, and the device checks the answer against the
  authority's own signatures rather than trusting the member.
  `encodeRekeyEvent({ commit: true })` writes the epoch commitment
  (`epochCommitment`) into the rekey body; `hostMemberEpochDesk` answers
  member requests (kinds 20471/20472, `MEMBER_EPOCH_KINDS`);
  `requestRoomEpoch({ members: memberEpochSource(...) })` asks members as
  well as the authority, and `requestMemberEpoch` asks members alone. Codecs:
  `encodeMemberEpochRequest`, `decodeMemberEpochRequest`,
  `encodeMemberEpochGrant`, `decodeMemberEpochGrant`, `readRekeyEvidence`,
  `deriveMemberEpochRequestKey`. Vectors: `vectors/member-epoch-vectors.json`
- The known-members gate (#207, `docs/member-epoch-catch-up.md`): once a
  room has removed anybody, both desks grant only to participants the room
  knows (`known`), and send anybody else to approval (`onUnknown`; the
  authority answers `refused: 'unknown'`, which `requestRoomEpoch` waits
  through). `encodeRekeyEvent({ members })` and `hostRoomEpoch({ members })`
  carry the authority's member list (`readMemberList` reads one)
- Seal keys (`docs/seal-key.md`): a credential may name a seal key
  (`createDeviceCredential({ seal })`, `generateSealKey`), and rekeys and
  both grants are sealed to the newest one the sender holds for a device
  instead of its device key, so a copied device heals once its credential
  lapses and the room rekeys. Recipients as `{ device, credential }`;
  `sealSks` on the readers; `credentialFor` on both desks;
  `credentialSeal`, `sealTarget`, `sealTo`, `openSealed`, `newerCredential`,
  `sealCredential`. Vectors: `vectors/seal-vectors.json`
- One-time senders (`docs/seal-key.md`, "One-time senders"):
  `oneTimeSender` on `encodeRekeyEvent` and `encodeEpochGrant` seals every
  copy from a fresh key named in a `from` tag, so a later copy of the
  authority's key opens no past copy; readers use `sealSender`. Off by
  default until every client's readers have shipped.
- Scheduled rekeys and the history window (`docs/scheduled-rekey.md`):
  `encodeRekeyEvent({ scheduled: true })` marks a turn of the key that
  removes nobody, read back as `RekeyNotice.scheduled` and
  `RekeyEvidence.scheduled`; `HISTORY_WINDOW_SECONDS`, `MAX_HISTORY_EPOCHS`
  and `epochsInWindow` are the rule for which left epochs a member reads;
  `encodeEpochGrant({ passed })` and `hostRoomEpoch({ past })` hand those
  epochs (`LeftEpoch`) to every device the authority grants, read back as
  `EpochGrant.passed`. Vectors: `vectors/schedule-vectors.json`
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
npm run generate-storage # regenerate vectors/storage-vectors.json (needs a prior build)
npm run bundle-check # esbuild browser bundle check (needs a prior build)
npm run check        # typecheck + test + diff-source
```

There is no separate lint script.

## Licence

MIT

### Live persistent admission (opt-in codecs)

`parseLivePersistentEvent` bounds raw event JSON and refuses duplicate fields.
`encodeLivePersistentDescriptor` / `decodeLivePersistentDescriptor` carry
routing metadata alongside an unchanged persistent invitation link.
`encodeLivePersistentRequest` / `decodeLivePersistentRequest` and
`encodeLivePersistentAnswer` / `decodeLivePersistentAnswer` implement a fresh,
root-signed challenge/answer with no delegation. The answer retains epoch-zero
capability separately from `epochHint`. Constants bound request/answer lifetimes
to 90/30 seconds. `LIVE_PERSISTENT_ADMISSION_LABELS` freezes its distinct KDF.

These functions are codecs, not an offline join API. The host must have exclusive
durable lifecycle authority; the client must complete authenticated epoch
admission before publishing, including at epoch zero. No application enables
this profile automatically. See [the wire profile and integration gates](docs/live-persistent-admission.md).
Frozen synthetic fixtures are in `vectors/live-persistent-vectors.json`; run
`npm run build && npm run generate-live-persistent` to regenerate them.

## Authenticated invitation refusal (0.12.0)

`encodeInvitationDecline` and `decodeInvitationDecline` exchange a private,
request-bound refusal from the pinned inviter or a current delegated responder.
The version-3 refusal body uses reply kind 20467 and contains no room secret or
new delegation. Legacy version-2 grant readers ignore it.
`requestRoomAdmissionCapability` stops retries and rejects with
`InvitationDeclinedError` after verifying a refusal. Existing host `admit` hooks
returning false still leave requests unanswered; hosts must explicitly publish
a refusal using their guarded, acknowledged decision path. No UI integration or
physical acceptance is claimed by this protocol release.

### MLS admission v4 evidence codec

The separate opt-in v4 codec binds an encrypted account/device request to signed
keeper consent and an expected MLS group. It uses existing 20466/20467 carriers,
strict canonical arrays and a fixed payload bucket. Existing room links/codecs
are unchanged. Import from `@forgesworn/fold-kit/mls-admission`; see [API and boundaries](docs/mls-admission-v4.md).

Exports: `encodeMlsInvitationV4`, `readMlsInvitationV4`,
`mlsAdmissionProofTemplatesV4`, `encodeMlsAdmissionRequestV4`,
`decodeMlsAdmissionRequestV4`, `readMlsAdmissionRequestV4`,
`encodeMlsAdmissionAnswerV4`, `decodeMlsAdmissionAnswerV4`,
`readMlsAdmissionAnswerV4`, `MLS_ADMISSION_LABELS`,
`MLS_ADMISSION_PLAINTEXT_BYTES`, `MLS_ADMISSION_CIPHERTEXT_CHARACTERS`;
types `VerifiedMlsAdmissionRequest` and `VerifiedAdmissionAnswer`.

Verified answers are evidence only. Actual admission requires new purpose-bound
vault proof and authoritative live box/Link role-witness APIs, a conditional
keeper revision at the effect boundary, current custody/consent, durable counter
and one-shot operation storage, and VMLS/Welcome verification. No browser
admission, authority factory, transport, storage or automatic retry is provided.
