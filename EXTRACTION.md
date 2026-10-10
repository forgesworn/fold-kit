# Extraction evidence

Prepared from KithMoot branch `test/circle-vectors` (PR #206, not merged at
extraction time), commit `5babfec`. That branch is origin/main `8260c60`
plus the T0 wire-compatibility work: `vectors/circle-vectors.json`,
`vectors/generate-circle.mjs`, `vectors/verify-circle.test.ts`,
`src/labels.test.ts` and the pure `*_LABELS`/`*_INFO` exports the extraction
plan required before any code moved. The source checkout used for the
extraction and for `scripts/diff-source.mjs` was not modified.

Prepared under a private extraction plan (task T1.1) that also covers work
outside this repository's scope; see `docs/extraction-plan-excerpt.md` for
the parts of it this repository's own docs refer to.

## What moved (§1.1)

Copied with only import paths changed (verified byte-identical against the
pinned commit by `scripts/diff-source.mjs`, whole-file comparison):

| Kit file | Source file |
|---|---|
| `src/hex.ts` | `src/hex.ts` |
| `src/verify.ts` | `src/verify.ts` |
| `src/identity.ts` | `src/identity.ts` |
| `src/credential.ts` | `src/credential.ts` |
| `src/room.ts` | `src/room.ts` |
| `src/network-hints.ts` | `src/network-hints.ts` |
| `src/display-name.ts` | `src/display-name.ts` |
| `src/link.ts` | `src/link.ts` |
| `src/lane.ts` | `src/lane.ts` |
| `src/invitation.ts` | `src/invitation.ts` (`./relay-pool.js` import → `./transport.js`) |
| `src/persistent-invitation.ts` | `src/persistent-invitation.ts` (same rewrite) |
| `src/epoch.ts` | `src/epoch.ts` (same rewrite) |
| `test/sim-relay.ts` | `test/sim-relay.ts` (same rewrite) |

Unit tests moved with their module, unchanged, for every file above except
`persistent-invitation.test.ts` (see "Adaptations" below). `test/fake-socket.ts`
did not move: it is only used by `relay-pool.test.ts` and
`relay-pool-bad-relays.test.ts`, which belong to the relay subpath (T2.2,
not this task).

## Splits (§1.1)

Verified chunk-by-chunk (verbatim doc comment plus declaration) against the
pinned commit by `scripts/diff-source.mjs`:

- **`kinds.ts`** → this kit's `src/kinds.ts` is a subset: `CREDENTIAL`,
  `CHAT`, `INVITATION_REQUEST`, `INVITATION_GRANT`, `INVITATION_RETIREMENT`,
  `GROUP_INVITATION`, `ROOM_REKEY`, `EPOCH_REQUEST`, `EPOCH_GRANT`, each
  copied with its doc comment unchanged. `CHAT` (1460) is included because
  a downstream app's own board events are designed to share KithMoot's
  chat kind (see `docs/extraction-plan-excerpt.md`).
- **`types.ts`** → this kit's `src/types.ts` is a subset: `DeviceCredential`,
  `AccessTier`, `AgentRule`, `RoomPolicy`, `KindredProof`. `Reachability`
  (imported by KithMoot's `types.ts` for `RosterEntry`, `AssistOffer` and
  others) is not needed by this subset and does not move - the plan's
  "Corrections after the T0 vector review" flags this explicitly.
- **`access.ts`** → this kit's `src/access.ts` keeps `issueKindredProof`,
  `evaluateAccess`, the `canonicalMessage` helper and `ACCESS_LABELS`, all
  unchanged. `evaluateAgentAccess` stayed in KithMoot: it needs
  `ownership.ts` and `RosterEntry`, neither of which moved.
- **`chat.ts`** → `deriveChannel`, `CHANNEL_ID_INFO`, `CHANNEL_KEY_INFO` and
  `MAX_CHANNEL_NAME_LENGTH` moved into this kit's new `src/channel.ts`
  (renamed from the source's `CHAT_LABELS` to `CHANNEL_LABELS`, since the
  export now lives in its own file - the two frozen string values are
  unchanged). `ChatLog` and the chat event codecs stayed in KithMoot.

## What did not move (per the plan's corrections)

- The relay pool (`relay-pool.ts`, `relay-auth.ts`, `anonymous.ts`) stays in
  KithMoot until T2.2, after its churn settles (Decision 8). This kit
  declares its own `RelayTransport` interface in `src/transport.ts`
  (`publish`/`subscribe`/`close`) rather than importing KithMoot's - the
  three codecs that need a transport (`epoch.ts`, `invitation.ts`,
  `persistent-invitation.ts`) only ever call those three methods.
- `Reachability` stays in KithMoot (see "Splits" above).

## Vectors

- `vectors/kithmoot-vectors.json`: the circle-layer subset of KithMoot's own
  vector file - the groups `roomDerivation`, `channelDerivation`, `joinUrl`,
  `deviceCredential`, `kindredProof`, `accessEvaluation`, `roomEpoch` and
  `epochRequestAdmission`, copied group-for-group with no edits (same
  `protocolVersion`/`nostrToolsVersion` header). The other groups in
  KithMoot's file (roster event, signal wrap, room descriptor, TURN
  credential, agent ownership, chat attachment, approval control,
  verification words, the message layer) belong to modules that did not
  move and are not carried here.
- `vectors/circle-vectors.json`: copied whole and unedited from the pinned
  commit - every one of its 8 groups (`linkEnvelope`, `invitationEnvelope`,
  `persistentInvitation`, `epochGrant`, `epochRequest`, `personCredential`,
  `channelsSignature`, `accessEvaluation`) belongs to the circle layer.
- `vectors/lib/determinism.mjs`, `vectors/lib/fixtures.mjs`: copied
  unchanged. Both are pure, labelled-input helpers with no KithMoot-specific
  behaviour.
- `vectors/verify.test.ts`: adapted from KithMoot's `vectors/verify.test.ts`
  - only the describe blocks for the 8 circle groups above, with
  `deriveChannel`'s import moved from `../src/chat.js` to `../src/channel.js`.
  Every retained assertion is unchanged.
- `vectors/verify-circle.test.ts`: copied unchanged except one comment line
  naming the private planning document this repository does not name (see
  "Public repository naming" below) - every import it needs (`kinds.js`,
  `room.js`, `link.js`, `network-hints.js`, `display-name.js`,
  `invitation.js`, `persistent-invitation.js`, `credential.js`, `epoch.js`,
  `access.js`) already matches this kit's module layout one-to-one.

## Labels

`src/labels.test.ts` is adapted from KithMoot's own label test: same
scanning regex and per-module ownership check, cut down to the 15 labels
this kit's moved modules own (KithMoot's full frozen list has more, owned by
modules that stayed - roster, signalling, pairing, call bell, and so on).
Every label byte value is unchanged from KithMoot's frozen list.

## Adaptations (not wire changes)

- `src/persistent-invitation.test.ts` drops one upstream test ("lets an
  agent join and send chat from only stored admission") that drives
  `RoomAgent.join` - an app-level integration point (`agent.ts`, `chat.ts`)
  that is not part of this kit's boundary. The `SimRelay`/`SimTransport`
  replay path that test also exercises is already covered by the other
  tests in the same file.
- `src/display-name.test.ts` drops one upstream describe block ("the render
  path" / "never puts a display name through innerHTML"), which scans
  KithMoot's `app/src/main.ts` - the PWA source, which does not exist in
  this kit. The rest of the file, including the NUL-byte control-character
  fixture (see its own header comment), is unchanged.
- `src/kinds.test.ts` and `src/channel.test.ts` are new files: the former
  keeps the "circle-layer kind numbers" uniqueness check from KithMoot's
  `src/api-surface.test.ts` (whose snapshot machinery tracks KithMoot's
  whole library surface and stayed in KithMoot); the latter keeps the two
  `deriveChannel`-only cases from KithMoot's `src/chat.test.ts` "channels"
  describe block (the others need `ChatLog`/`encodeChatEvent`, which stayed
  in KithMoot).

## Package

ESM only, `exports` for `.` (everything), `./lane` (lane helpers only) and
`./package.json`, peer dependencies (`nostr-tools >=2.24.2 <3`,
`@noble/hashes ^1.8.0`, `@noble/curves ^2.0.1`) matching KithMoot's pinned
versions so a consumer keeps a single copy of each, `engines.node >=22.13`,
`sideEffects: false`. `@noble/hashes` is pinned to its 1.x major only:
this kit's `@noble/hashes` imports have no `.js` suffix and its `hkdf`
calls pass a string `info` argument, and 2.x's `exports` map only resolves
`.js`-suffixed subpaths while its `hkdf` rejects a string `info` - so 2.x
cannot satisfy these imports as written.

## Phase 3 additions (T3.1, T3.3): new code, not moved from KithMoot

The plan's Phase 3 (`docs/extraction-plan-excerpt.md`, gaps G1 and G3) calls
for new kit code beyond what moved from KithMoot. Two tasks are done:

- **T3.1, `src/scoped.ts`** (G1): `deriveScoped(epoch, label)`, an
  HKDF-SHA256 derivation from an epoch's KEY under an app-defined labelled
  namespace, so a downstream app (the private planning document's board
  tool, for one) can derive its own payload keys and stream ids under the
  same epoch as the roster and the chat - rotating together on a rekey -
  without ever colliding with, or being mistaken for, one of this kit's own
  derivations. Refuses this kit's own protocol namespace (checked via a
  prefix built by string concatenation rather than a literal, so the check
  itself does not add a new entry to `src/labels.test.ts`'s frozen scan -
  see the comment at its call site) and any label outside
  `^[a-z0-9-]{1,64}/v[0-9]{1,9}/[\x21-\x7e]{1,200}$` - the namespace and
  version segments are capped (64 bytes, 9 digits) because a label is always
  a short, fixed, hand-written string, never something worth accepting
  unboundedly just because the regex could technically match it.
- **T3.3, `src/sub-cert.ts`** (G3): `createSubKeyCertificate` /
  `verifySubKeyCertificate`, a sub-key certificate - a small, never-published
  kind-20460 event with `scope: "sub"`, signed by a credentialled device,
  binding an app-derived key (typically a `deriveScoped` output) to that
  device for one scoped id. `verifyDeviceCredential` already refuses any
  `scope` it does not recognise, so this new form can never be accepted as a
  room or person credential by the existing, unmodified verifier - no change
  to `credential.ts`'s verification logic was needed for this task.
  Verification is strict and canonical: exactly four tags, each exactly
  `[name, value]`, in a fixed order (`d`, `device`, `expiration`, `scope`);
  `content` must be the empty string; `expiration` must be a canonical
  decimal integer (no sign, no `0x` prefix, no fraction, no leading zeros,
  no surrounding whitespace) compared as the EXACT TAG STRING - not
  numerically - against the accompanying device credential's own
  `expiration` tag. `verifySubKeyCertificate` takes that credential event
  directly (`opts.credential`, already verified by the caller via
  `verifyDeviceCredential`) and reads its `device` and `expiration` tags
  itself, rather than trusting a caller to have copied them out correctly -
  an earlier revision took `device`/`credentialExpiresAt` as separate
  caller-supplied options, which an independent review found let the two
  drift apart from whatever `verifyDeviceCredential` had actually accepted.
  `createSubKeyCertificate` validates its own inputs before asking a signer
  to sign anything (`signerId`/`subKeyPubkey` must be 32-byte hex,
  `expiresAt` a safe integer strictly in the future).

Both are pure additions: no existing exported function's signature or body
changed, and both are covered by `src/scoped.test.ts` / `src/sub-cert.test.ts`
(unit tests, including a mutation-tested refusal for every security-relevant
check - see "Mutation testing" below) and `vectors/fold-vectors.json`
(known-answer vectors, generated by `scripts/generate-fold.mjs` and
independently recomputed against `src/` by `vectors/verify-fold.test.ts`).
Every negative certificate vector is validly signed (re-signed under its
mutated tags/content) rather than reusing the positive certificate's stale
signature over different bytes, so each one fails for exactly the reason
under test. `vectors/verify-fold.test.ts` also recomputes every
`deriveScoped` vector a second way, calling `@noble/hashes`' `hkdf` directly
rather than `deriveScoped`, so a shared bug between the generator and
`deriveScoped` itself cannot round-trip undetected. Unlike
`kithmoot-vectors.json` and `circle-vectors.json`, this vector file has no
upstream KithMoot counterpart and is not covered by `scripts/diff-source.mjs`.

The forgesworn/kithmoot#205 credential fix is a separate change, on its own
branch/PR (`fix/restamp-205`) based on this one: the `feat/scoped-keys` tip
this branch is based on makes no change to `credential.ts` at all; only the
commit below does.

### Mutation testing

Every security-relevant check in `src/scoped.ts` and `src/sub-cert.ts` was
mutated (the check deleted, or its condition forced to never fire) one at a
time, and the full targeted test suite (`src/scoped.test.ts`,
`src/sub-cert.test.ts`, `vectors/verify-fold.test.ts`) was re-run after each
mutation. All 29 mutations were killed (caused at least one test to fail):
3 in `scoped.ts` (the protocol-namespace refusal, the label-pattern check,
the epoch-key-length check) and 26 in `sub-cert.ts` (every tag-name check
individually - `d`, `device`, `expiration` and `scope`, each checked at its
own fixed position rather than only via a full reorder - the tag-count
check, the per-tag-shape check, the scope-value check, the signer-id check,
the sub-key/message-signer check, the credential-missing-device-tag check,
the wrong-device check, the canonical-expiration-format check, the
credential-missing-expiration-tag check, the expiration-equality check, the
expired check, the at/skew bound, the certificate signature check, both
mint-time hex-shape validations, the mint-time future-integer check, and
all four of `createSubKeyCertificate`'s post-signing equality checks -
signer pubkey, kind/content, tags, and `verifyEventUncached`). Each mutation
was reverted immediately after its run; none is present in the committed
code. The `RestampedCredentialExpiryError`/`overBySeconds` check the #205
fix below adds was likewise mutated and killed (see that section).

## The #205 fix: the one deliberate difference from the pinned source

`src/credential.ts` is not quite byte-identical to the pinned commit: it
carries one small, deliberate fix for
[forgesworn/kithmoot#205](https://github.com/forgesworn/kithmoot/issues/205).

The bug: `createDeviceCredential`'s 30-day cap on a person-scope credential
is checked against the *requested* `now` (`opts.expiresAt - now`), but
`verifyDeviceCredential`'s matching check is against the *signed*
`created_at` (`expiresAt - cred.created_at`). A remote signer (a bunker, a
phone) that restamps `created_at` to its own, earlier clock - which
`createDeviceCredential` deliberately tolerates, since some signers do this
and nothing here should assume otherwise - can then produce a credential
that mints successfully but is refused as `"longer than 30 days"` by every
verifier, including `verifyDeviceCredential` itself.

The fix is two small additions, both stripped by name in
`scripts/diff-source.mjs` (see below): a typed error,
`RestampedCredentialExpiryError` (exported from the package root, carrying
`overBySeconds`, so a caller can tell this failure apart from the function's
other, unrelated failure modes and retry specifically for it), and a check
right after the existing post-signing checks in `createDeviceCredential`
that re-measures the cap using the verifier's own calculation (against
`signed.created_at`) and throws that error immediately if it is over, rather
than returning a credential doomed to be refused everywhere. A caller that
hits this (as the downstream sync spec's own retry logic does) asks again
with a shorter `expiresAt` margin. `verifyDeviceCredential` itself is
untouched - its measurement was already correct; only the mint side was
checking the wrong clock.

`scripts/diff-source.mjs` proves these two additions are the *only*
difference: it strips exactly these two declared blocks (each matched
verbatim) from `src/credential.ts` before comparing the rest of the file,
byte for byte, against the pinned commit. If either block's text ever
drifted from what the script declares, the strip would stop matching and
the check would fail loudly rather than silently widening what counts as
"the declared difference".

This fix changes the behaviour one existing vector was written to pin: the
`personCredential`/`refused-over-30-days` vector in `circle-vectors.json`
(KithMoot's own `M15`) exercises exactly the restamp-at-the-cap scenario the
bug describes, and was frozen expecting a successful mint followed by a
verifier refusal. That vector's `output` keeps both halves of M15's
original coverage - `event` and `result` are still the exact over-cap event
a pre-#205 mint would have produced (built deterministically in the test,
since the real `createDeviceCredential` now refuses to produce it) and
`verifyDeviceCredential`'s own refusal of it, byte-identical to before - and
adds `mintThrew`, the new mint-time refusal message. The vector's `note` and
the corresponding test in `vectors/verify-circle.test.ts` are updated to
check all three - the issue itself anticipated this ("The vectors pin
current [i.e. buggy] behaviour; this fix is separate"). Every other vector
in both `kithmoot-vectors.json` and `circle-vectors.json`, and their
generators, are untouched. `src/credential-205.test.ts` adds two more cases
through the real function: the same at-the-cap restamp now throwing
(asserted as `RestampedCredentialExpiryError`, with a mutation-tested check
on `overBySeconds`), and a one-hour-margin request succeeding under the same
restamp.

**This is a breaking behaviour change for `createDeviceCredential`, called
out in `CHANGELOG.md`.** KithMoot's own `src/credential.ts` has the same
bug, unfixed; `CHANGELOG.md` says what has to change there (`M15` in its
`vectors/verify-circle.test.ts` and `vectors/generate-circle.mjs`) in a
paired PR.

## Conference rooms: declared additions to three moved modules

0.3.0 adds conference rooms - a persistent group with a fixed end, carried
as a NIP-40 expiration - to `invitation.ts` (retirement `endsAt`),
`persistent-invitation.ts` (invitation `endsAt`, body `ends`, the decoder's
tag/body agreement check, earliest end wins in
`requestPersistentRoomAdmission`) and `epoch.ts` (`expiresAt` on the rekey,
request and grant encoders and both desk functions). The rule itself lives
in a new module, `src/expiration.ts`, which moved from nowhere.

Each addition is optional and additive: with it absent, every event these
modules sign is byte-identical to before, and every existing vector still
verifies. `scripts/diff-source.mjs` lists each added or altered line in
`CONFERENCE_CHANGES` as `[kit text, pinned source text, count]`, checks
each occurs exactly `count` times, puts the source text back, and then
compares the whole file against the pinned commit as before - so these are
the only differences, and a drifted line fails the check rather than
widening it. KithMoot's own copies of these modules are re-export shims
since its cutover, so it picks this up on its next version bump.

## Room relays: declared additions to `persistent-invitation.ts`

0.4.0 adds the room's own relays to the group invitation body, after
`ends`: the relays a room is created on, which every member's pool then
includes. The rule (one to eight distinct, safe, canonical URLs) lives in a
new module, `src/invitation-relays.ts`, which moved from nowhere. With no
`relays` the body is byte-identical to 0.3.0's. `scripts/diff-source.mjs`
declares each added line in `ROOM_RELAY_CHANGES` as 0.4.0 text against
0.3.0 text, applied before `CONFERENCE_CHANGES`, so the whole-file
comparison against the pinned commit still holds.

## Member epoch catch-up: declared additions to `epoch.ts`

Unreleased. Any current member can now hand an admitted, non-removed device
the epochs it missed, with the authority's own rekeys as evidence (see
`docs/member-epoch-catch-up.md`). The new code lives in two new modules
that moved from nowhere: `src/epoch-commit.ts` (the commitment, a leaf with
no imports from `epoch.ts`, so there is no import cycle) and
`src/member-epoch.ts` (the member request and grant, the desk and the
requester). Its kinds, 20471 and 20472, are exported from there as
`MEMBER_EPOCH_KINDS` rather than added to `KINDS`, whose body
`scripts/diff-source.mjs` proves is exactly the pinned source's.

`epoch.ts` gains two optional, additive options: `commit` on
`encodeRekeyEvent` (writes the commitment into the body) and `members` on
`requestRoomEpoch` (a second source of answers). With both absent, every
event is byte-identical to 0.4.0's and every existing vector still verifies.
`scripts/diff-source.mjs` declares each added line in
`MEMBER_EPOCH_CHANGES`, as new text against 0.4.0 text, applied before
`ROOM_RELAY_CHANGES` and `CONFERENCE_CHANGES`, so the whole-file comparison
against the pinned commit still holds.

## Seal keys: declared additions to `credential.ts` and `epoch.ts`

0.7.0. A device credential may name the device's seal key, and rekeys and
epoch grants are sealed to it instead of the device key (see
`docs/seal-key.md`). The new code lives in `src/seal.ts`, which moved from
nowhere. `credential.ts` gains the optional `seal` on
`createDeviceCredential`; `epoch.ts` gains seal-keyed recipients, `sealSks`
on the decoders and `requestRoomEpoch`, `credential` on `encodeEpochGrant`,
`credentialFor` on `hostRoomEpoch`, and `sealCredential`. With no seal key
anywhere, every event is byte-identical to 0.6.0's. `scripts/diff-source.mjs`
declares each hunk in `SEAL_CHANGES`, as 0.7.0 text against 0.6.0 text,
applied before every other change set but `SCHEDULE_CHANGES` (and, for
`credential.ts`, before the #205 blocks are stripped).

## Scheduled rekeys: declared additions to `epoch.ts`

0.8.0. A rekey may be marked `scheduled`, the history window is a shared
rule (`HISTORY_WINDOW_SECONDS`, `MAX_HISTORY_EPOCHS`, `epochsInWindow`), and
the authority's grant carries the window's left epochs (`passed`, and `past`
on `hostRoomEpoch`). See `docs/scheduled-rekey.md`. A rekey without the
marker, and a grant without `passed`, is byte-identical to 0.7.0's.
`scripts/diff-source.mjs` declares each hunk in `SCHEDULE_CHANGES`, as 0.8.0
text against 0.7.0 text, applied before every other change set but `DESTRUCT_CHANGES`. The matching
reader changes in `member-epoch.ts` (`RekeyEvidence.scheduled`, and `leftAt`
on a member grant's passed epochs) need no declaration: that module is new
code and not compared against the pinned source.

## Self-destructing rooms: declared additions to three moved modules

0.9.0. An optional `destruct: true` in the group invitation body
(`persistent-invitation.ts`), in an ended room's retirement
(`invitation.ts`) and in a closing rekey's body (`epoch.ts`), each surfaced
on its reader, and kept by `requestPersistentRoomAdmission` if any signed
copy carries it. See `docs/room-destruct.md`. With the flag absent every
event is byte-identical to 0.8.0's. `scripts/diff-source.mjs` declares each
hunk in `DESTRUCT_CHANGES`, as 0.9.0 text against 0.8.0 text, applied before
every other change set. The matching reader change in `member-epoch.ts`
(`RekeyEvidence.destruct`) needs no declaration.

## Public repository naming

This repository is public. It does not name the private downstream app that
motivated some of the moves and split points above (the board-events kind
share, for instance) - see `docs/extraction-plan-excerpt.md`, which carries
the neutral wording used throughout this repository's docs, comments and
tests in place of that name.

## For KithMoot's cutover (T2.1, not this task)

Notes for whoever writes KithMoot's re-export shims, so the codec cutover
does not silently change KithMoot's own public surface:

- Shims must use named `export { … }` / `export type { … }`, not
  `export * from '@forgesworn/fold-kit'`. A wildcard re-export would pull in
  all of this kit's ~96 root exports, including several (such as `KINDS`
  itself, or `RelayTransport`) that KithMoot's own modules already export
  under the same name from elsewhere - and it would change KithMoot's
  `src/api-surface.test.ts` snapshot for every shimmed file, which is
  exactly what that snapshot exists to catch.
- The `chat.ts` shim must not re-export `CHANNEL_LABELS`: that name does
  not exist in KithMoot today (its own label is `CHAT_LABELS`, kept in
  KithMoot since `ChatLog` and the chat codecs did not move), and
  `src/labels.test.ts` would otherwise see two different exported lists
  claiming the same two label strings.
- The `kinds.ts` shim: KithMoot's `KINDS` object should spread this kit's
  `KINDS` first, then KithMoot's own remaining kind entries, and drop
  KithMoot's own now-duplicate `CHAT` field (this kit's `KINDS.CHAT` is
  byte-identical to KithMoot's, so the spread order does not change the
  value - only which module's object literal defines it).
- The `types.ts` shim must `import type` whichever of this kit's types
  KithMoot's own `types.ts` still uses (`DeviceCredential`, `AccessTier`,
  `RoomPolicy`, `KindredProof`) rather than redeclaring them, so there is
  exactly one definition of each.

## Validation

- `npm run check` (typecheck + test + diff-source) on Node 22.13 and Node
  24: green on both.
- `scripts/diff-source.mjs` against commit `5babfec`: zero differences.
- Both vector files verify against this kit's own functions.
- `scripts/bundle-check.mjs`: esbuild browser bundle of both entry points,
  no `node:` import, within the recorded size budget.
- `scripts/tarball-smoke.mjs`: `npm pack`, install into a scratch directory,
  import and exercise every export from both entry points.

KithMoot has cut over to this kit (T2.1) and pins an exact npm version;
its moved files are re-export shims. Any change here that alters behaviour
KithMoot's vectors record (for example the #205 fix) lands in KithMoot in
the same PR as the version bump.

## Live persistent admission

`src/live-persistent-admission.ts` is a new opt-in profile, not a change to a
moved invitation module. It uses kinds 20466/20467 with a distinct request KDF
and body profile, preserves kind 1463 bytes, and grants no delegation. Its
descriptor, challenge and answer codecs own no transport or storage. The host
lifecycle journal, client epoch gate and physical transport remain separate
integration requirements; see `docs/live-persistent-admission.md`.

## Grant publication callbacks

The host's publication callbacks now follow settlement of the injected
transport's `publish(grant)` promise. `onGrantPublished(request)` correlates
success to the request; the legacy `onAdmitted(device)` observes the same
acknowledgement. `onGrantFailed(request, error)` exposes a rejected or throwing
send. A closed or retired host suppresses outstanding callbacks, and observer
exceptions cannot change the publication outcome. These are local API and
timing changes; request/grant encoders, kinds, envelopes and derivation labels
are unchanged. `GRANT_PUBLICATION_CHANGES` in `scripts/diff-source.mjs` reverses
the two exact interface/host hunks before comparing with the extracted source.

## Invitation account proof and bounded request lifecycle

The live invitation request now accepts an optional `accountProof`. The new
proof profile signs kind 20466 with exactly the tags
`t=kithmoot/v2/invitation-account-proof`, `d=<invitation id>` and
`p=<pinned inviter>`, content `{"v":1,"device":"<request device>"}` and the
outer request's timestamp. Its account pubkey must match `participant`.
The version-1 proof body is a new profile under its own domain; the existing
version-1 encrypted request body retains its bytes when the field is absent.
Existing readers ignore the optional field. No existing derivation label,
kind or grant format changes. The proof is nested inside the bearer-encrypted
request and must never be independently published.

`encodeInvitationAccountProof` validates the matching signer's actual returned
signature and context. `decodeInvitationRequest` exposes `verifiedParticipant`
only after an uncached verification of the matching proof. The existing
`participant` remains an unverified claim; invalid proofs do not prevent a
host from considering an anonymous/manual request, but cannot establish an
account's authority. Consumers must use `verifiedParticipant` for automatic
account-based admission. New known-answer vectors record the new profile,
legacy requests and forged or substituted nested proofs.

The request helper optionally creates the proof using its caller's matching
identity. Account signing and relay waiting share a deadline no longer than
the 90-second request freshness window. Cancellation or retirement suppresses
late signing/publication; only a cloned request key is erased. Host decisions
recheck freshness before granting and report expired decisions via the failure
observer. `INVITATION_ACCOUNT_CHANGES` in `scripts/diff-source.mjs` reverses
these exact additions before the previously declared changes and the complete
comparison with the pinned source. This is an additive public API release,
0.11.0; it does not make an unmodified consumer's admission policy safe.

## Authenticated admission refusal (0.12.0)

The new `invitation-decline.ts` codec uses a version-3 refusal envelope on the
existing encrypted reply kind 20467. The version-2 grant body, existing keys,
derivation labels and invitation URLs are unchanged. A refusal is addressed to
one request device and event ID, signed by the pinned root or authenticated via
its current bounded delegation chain; it carries no traffic secret or newly
issued authority. Bearer possession alone cannot refuse another guest.
New request helpers stop their immutable retries and erase only the owned
exchange key on an authenticated refusal. Earlier readers reject this envelope
as a grant and retain their previous bounded timeout. Host false decisions
retain their historical silence unless a consumer explicitly publishes the new
refusal. Concurrent authorised replies use the first valid received outcome; a
refusal does not revoke an already granted capability. `INVITATION_DECLINE_CHANGES`
reverses the exact helper import and response handling before all earlier
declared normalisations and the full pinned-source comparison. Synthetic known
answers cover the new profile and hostile request, authority and version changes.
