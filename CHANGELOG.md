# Changelog

This kit is pre-1.0 (see AGENTS.md "Release Notes"); a behaviour change on
`main` is still called out here, because `createDeviceCredential` is a
byte-identical copy of a KithMoot function (see EXTRACTION.md) and this is
the one place its behaviour has deliberately diverged.

## Unreleased

### Changed

- The known-members gate (#207). The epoch desks' admission proof is made
  under the epoch-0 room key, which a removed member keeps, so a removed
  person could ask again under a fresh participant key and be handed the
  current epoch. Once a room has removed anybody, `hostRoomEpoch` and
  `hostMemberEpochDesk` now grant only to participants for which the new
  `known(participant)` option says yes, and report anybody else through
  `onUnknown`: once per participant, and again every `reportUnknownEvery`
  seconds (default 60) while they keep asking. **A desk given no `known` lets nobody through after a
  removal**: wire `known` before taking this release. Rooms that have
  never removed anybody behave exactly as before.
- New refusal `'unknown'` (`EpochRefusal`): the authority's answer to a
  participant it does not know. Not final: `requestRoomEpoch` keeps asking,
  calls its new `onUnknown` once, and rejects with
  `EpochRefusedError('unknown')` only at its timeout. A decoder from 0.5.1
  reads it as no answer and keeps asking.

### Added

- `encodeRekeyEvent({ members })`: the authority's member list in the
  encrypted rekey body (after `commit`, before `keys`), removed
  participants dropped. Read as `RekeyNotice.members`,
  `RekeyEvidence.members` and `MemberEpochGrant.members`.
  `hostRoomEpoch({ members })` and `encodeEpochGrant({ members })` carry it
  in the authority's grant (`EpochGrant.members`). `readMemberList`.
  Omitted, every event is byte-identical to 0.5.1's.
- Vector `rekey-with-members` in `vectors/member-epoch-vectors.json`.

## 0.5.1

### Added

- `MemberEpochGrant.passed`: the epochs a member grant carried between the
  requester's and the one it hands over, oldest first, each proven by the
  next rekey in the chain as before. `requestRoomEpoch`'s grant carries it
  as an optional `passed` when a member answered. Wire unchanged; a
  consumer that ignores it behaves exactly as with 0.5.0. KithMoot uses it
  to read what was said in the epochs a returning device skipped, rather
  than reporting them lost.

## 0.5.0

### Added

- Member epoch catch-up: any current member can bring an admitted,
  non-removed device up to date while the authority is offline, and the
  device verifies the answer against the authority's signatures instead of
  trusting the member. See `docs/member-epoch-catch-up.md`.
  - `encodeRekeyEvent` takes an optional `commit: true`, which writes
    `commit: epochCommitment(roomId, epoch, secret)` into the encrypted
    body (key order `v, epoch, removed, by, closed, commit, keys`; the body
    version stays 1 and a 0.4.0 reader ignores the key). Without it the
    event is byte-identical to 0.4.0's.
  - New module `epoch-commit.ts`: `epochCommitment`, `EPOCH_COMMIT_PREFIX`.
  - New module `member-epoch.ts`: kinds 20471 (member epoch request) and
    20472 (member epoch grant) as `MEMBER_EPOCH_KINDS`;
    `hostMemberEpochDesk`, `memberEpochSource`, `requestMemberEpoch`,
    `encodeMemberEpochRequest`, `decodeMemberEpochRequest`,
    `encodeMemberEpochGrant`, `decodeMemberEpochGrant`, `readRekeyEvidence`,
    `deriveMemberEpochRequestKey`, `MAX_MEMBER_EPOCH_CHAIN`.
  - `requestRoomEpoch` takes an optional `members` source; without it, it
    behaves exactly as before.
  - `memberEpochSource` watches the room's rekeys and refuses a member
    grant that stops short of the newest authority-signed one, so a member
    removed at epoch E cannot hold a requester at E-1 when the caller
    passes no `expected`.
  - Member grants (20472) are signed by a one-time key per grant, not the
    answering member's device key, so a grant does not publicly tie that
    device to the room. `MemberEpochGrant` has no `from`, and
    `encodeMemberEpochGrant` takes no `deviceSk`.
  - `memberEpochSource`'s `removed` is a function or an iterable read once,
    so a generator is not used up by the first grant.
  - Two new wire labels: `kithmoot/v1/epoch-commit:` and
    `kithmoot/v1/member-epoch-request-key`.
  - `vectors/member-epoch-vectors.json` (KithMoot vector format, shipped in
    the package) and `scripts/generate-member-epoch.mjs`.
- The browser bundle budget for the main entry rises to 64 KB minified /
  19 KB gzip (measured 51.2 / 14.9).

## 0.4.0

### Added

- Room relays: the relays a room is created on, carried in its signed group
  invitation so every member's pool includes them and two members can never
  end up on disjoint relays. `encodePersistentInvitation` takes an optional
  `relays`: one to eight distinct strings, each a safe relay URL
  (`isSafeRelayUrl`) in canonical form (`normalizeURL` from
  `nostr-tools/utils`, e.g. `wss://relay.example.com/`) with no
  credentials, else it throws. The encrypted v3 body carries them after
  `ends` (key order `v, room, secret, ends, relays`; the version stays 3).
  `decodePersistentInvitation` returns `relays` (and
  `PersistentRoomAdmission` gains it) and returns null for the whole
  envelope when the list is malformed - never a trimmed list.
  `requestPersistentRoomAdmission` keeps the relays of the newest signed
  copy (by `created_at`) that names any; a copy naming none says nothing
  about them, and between equal timestamps the first heard stays. Contrast
  `endsAt`, where the earliest end wins.
- `isInvitationRelays`, `requireInvitationRelays` and
  `MAX_INVITATION_RELAYS` (8): the rule, for callers that build the list.

With no `relays`, the body is byte-identical to 0.3.0's, and a 0.3.0
reader ignores the key. `scripts/diff-source.mjs` declares each added line
(see EXTRACTION.md "Room relays").

## 0.3.0

### Added

- Conference rooms: a persistent group that ends on a fixed date.
  `encodePersistentInvitation` takes an optional `endsAt` (unix seconds,
  after `now` and no more than 30 days beyond it, else it throws). With it,
  the encrypted v3 body carries `ends` (the version stays 3) and the kind
  1463 event carries a NIP-40 `['expiration', String(endsAt)]` tag, so
  relays drop the invitation when the room ends. `decodePersistentInvitation`
  returns `endsAt` (and `PersistentRoomAdmission` gains it) when the body
  has a positive whole-number `ends`; it returns null when an `expiration`
  tag is present and does not equal the body's `ends`, when there are two
  `expiration` tags, or when `ends` is malformed. `requestPersistentRoomAdmission`
  keeps the earliest `endsAt` among the signed copies it hears.
- `encodeInvitationRetirement` takes `endsAt`, tagging the kind 1461
  tombstone with the same expiration.
- `encodeRekeyEvent`, `encodeEpochRequest`, `encodeEpochGrant`,
  `hostRoomEpoch` and `requestRoomEpoch` take `expiresAt`, so a conference
  room's epoch events lapse with it.
- `withExpiration(tags, expiresAt)`, `isRoomEnds`, `requireRoomEnds` and
  `MAX_ROOM_ENDS_SECONDS`: the expiration rule every event signed for a
  conference room follows - add the end if the event has no expiration,
  keep an earlier one, lower a later one, never two.

With no `endsAt`/`expiresAt`, every encoder produces exactly the bytes it
did in 0.2.0. `scripts/diff-source.mjs` declares each added line (see
EXTRACTION.md "Conference rooms").

## 0.2.0

### Added

- `deriveScoped(epoch, label)` for app-defined keys under an epoch, and
  `createSubKeyCertificate` / `verifySubKeyCertificate` for never-published
  sub-key certificates (see README and `vectors/fold-vectors.json`).

### Changed (breaking behaviour, pre-1.0)

- **`createDeviceCredential` now throws for a person-scope credential a
  restamping signer would make unverifiable**
  ([forgesworn/kithmoot#205](https://github.com/forgesworn/kithmoot/issues/205)).
  Previously, a remote signer that restamped `created_at` to an earlier
  clock could make `createDeviceCredential` return a credential that every
  `verifyDeviceCredential` call would then refuse as `"longer than 30
  days"` - the mint-time cap was checked against the requested `now`, while
  the verifier checks against the signed `created_at`. `createDeviceCredential`
  now re-checks with the verifier's own measurement and throws a new typed
  error, `RestampedCredentialExpiryError` (exported from the package root),
  instead of returning a credential doomed to fail everywhere.
  - **Who is affected**: only callers passing `scope: 'person'` whose
    `identity.signEvent` may restamp `created_at` (a NIP-46 bunker, a NIP-55
    phone signer, or any other out-of-process signer) AND whose requested
    `expiresAt` is close enough to `now + 30 days` that the restamp pushes
    the real duration over the cap. A local signer (`localIdentity`), or any
    signer that does not restamp, is unaffected. Room-scope credentials
    (`roomId` set, no `scope`) have no 30-day cap and are unaffected.
  - **Migration**: catch `RestampedCredentialExpiryError` and retry with a
    shorter `expiresAt` margin (this kit's own vectors use a one-hour
    margin: `now + PERSON_CREDENTIAL_MAX_SECONDS - 3600`), as the downstream
    sync spec that reported this issue already does.
  - **KithMoot pairing required**: KithMoot has cut over to this kit and
    pins `@forgesworn/fold-kit` exactly, so its `src/credential.ts` is a
    re-export and picks this fix up on its next version bump. That bump must
    land in the same KithMoot PR as the matching change to its
    `vectors/verify-circle.test.ts` `refused-over-30-days` case (M15) and
    `vectors/generate-circle.mjs`, which still expect the mint to return the
    over-cap event rather than throw.
