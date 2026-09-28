# Extraction evidence

Prepared from KithMoot branch `test/circle-vectors` (PR #206, not merged at
extraction time), commit `5babfec`. That branch is origin/main `8260c60`
plus the T0 wire-compatibility work: `vectors/circle-vectors.json`,
`vectors/generate-circle.mjs`, `vectors/verify-circle.test.ts`,
`src/labels.test.ts` and the pure `*_LABELS`/`*_INFO` exports the extraction
plan required before any code moved. The source checkout used for the
extraction and for `scripts/diff-source.mjs` was not modified.

Plan: `docs/plans/2026-09-28-circle-kit-extraction.md` in the `girnel`
repository, task T1.1.

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
  copied with its doc comment unchanged. `CHAT` (1460) is included per the
  plan's Decision 3: Girnel's board events share KithMoot's chat kind.
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
- `vectors/verify-circle.test.ts`: copied unchanged - every import it needs
  (`kinds.js`, `room.js`, `link.js`, `network-hints.js`, `display-name.js`,
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

ESM only, `exports` for `.` (everything) and `./lane` (lane helpers only),
peer dependencies (`nostr-tools >=2.24.2 <3`, `@noble/hashes ^1.8.0 || ^2.0.0`,
`@noble/curves ^2.0.1`) matching KithMoot's pinned versions so a consumer
keeps a single copy of each, `engines.node >=22.13`, `sideEffects: false`.

## Validation

- `npm run check` (typecheck + test + diff-source): see the session's report
  for the exact Node versions this ran on.
- `scripts/diff-source.mjs` against commit `5babfec`: zero differences.
- Both vector files verify against this kit's own functions.
- `scripts/bundle-check.mjs`: esbuild browser bundle of both entry points,
  no `node:` import, within the recorded size budget.
- `scripts/tarball-smoke.mjs`: `npm pack`, install into a scratch directory,
  import and exercise every export from both entry points.

KithMoot has not cut over to this kit (T2.1); it still carries its own copy
of every module listed above. A new npm release under `0.1.0` is pending the
owner's decision (T4.0); until then, a consumer pins the exact Git commit
that publishes this file.
