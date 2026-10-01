# Changelog

This kit is pre-1.0 (see AGENTS.md "Release Notes"); a behaviour change on
`main` is still called out here, because `createDeviceCredential` is a
byte-identical copy of a KithMoot function (see EXTRACTION.md) and this is
the one place its behaviour has deliberately diverged.

## Unreleased

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
