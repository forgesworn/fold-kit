# AGENTS.md: fold-kit

Instructions in this file apply to the entire repository.

## Project Summary

Circle primitives for private Nostr groups nobody operates: epoch keys, link
invites, removal by rekey, device credentials. Extracted from
[KithMoot](https://github.com/forgesworn/kithmoot) for reuse by other
ForgeSworn clients (see EXTRACTION.md for the exact source commit and what
moved). Framework-free: owns no storage, UI, relay defaults or identity
keys, and does no relay I/O of its own - callers inject a `RelayTransport`.
ESM-only package (`"type": "module"`), requires Node.js `>=22.13`.

## Commands

```bash
npm install           # install dependencies
npm run build          # compile TypeScript into dist/
npm test               # run the Vitest suite, including both vector files
npm run typecheck       # type-check src/ and test/, no emit (vectors/ is vitest-only, matching KithMoot)
npm run vectors         # run only the vector-verification suites
npm run diff-source      # compare moved modules against the pinned source commit
npm run generate-fold    # regenerate vectors/fold-vectors.json (T3.1/T3.3/#205 vectors; needs a prior build)
npm run generate-member-epoch  # regenerate vectors/member-epoch-vectors.json (needs a prior build)
npm run bundle-check     # esbuild browser bundle check (needs a prior build)
npm run tarball-smoke    # npm pack, install into a scratch dir, import every export
npm run check            # typecheck + test + diff-source
npm run prepublishOnly   # check + bundle-check + tarball-smoke; runs automatically before npm publish
```

There is no separate lint script.

`npm run diff-source` needs a local checkout of the pinned KithMoot source
commit; point `FOLD_KIT_SOURCE_DIR` at it. KithMoot is public, so CI checks
out the pinned commit itself and sets `FOLD_KIT_SOURCE_DIR` before `npm run
check` runs (see `.github/workflows/ci.yml`). With no `FOLD_KIT_SOURCE_DIR`
set at all - the default for a local run with no KithMoot checkout to
hand - it prints a notice and exits 0 rather than failing.

## Repository Structure

- `src/` - the library. Modules mirror the KithMoot files they were copied
  from (see EXTRACTION.md), except `kinds.ts`, `types.ts` and `access.ts`
  (subsetted), `channel.ts` (one function extracted from KithMoot's
  `chat.ts`), `transport.ts` (new: this kit's own `RelayTransport`
  interface), `scoped.ts`/`sub-cert.ts` (new: T3.1/T3.3, not moved from
  anywhere - see EXTRACTION.md "Phase 3 additions"), and `expiration.ts`
  (new: the conference-room expiration rule - see EXTRACTION.md "Conference
  rooms", which also covers the declared additions it brought to
  `invitation.ts`, `persistent-invitation.ts` and `epoch.ts`), and
  `invitation-relays.ts` (new: the room-relay list rule - see EXTRACTION.md
  "Room relays"), and `epoch-commit.ts`/`member-epoch.ts` (new: member epoch
  catch-up - see EXTRACTION.md "Member epoch catch-up" and
  `docs/member-epoch-catch-up.md`).
- `test/sim-relay.ts` - an in-process relay simulator (`SimRelay`,
  `SimTransport`) used by the invitation, persistent-invitation and epoch
  test suites.
- `vectors/` - known-answer wire-format vectors: `kithmoot-vectors.json` (a
  circle-layer subset of KithMoot's own vector file, byte-identical
  group-for-group), `circle-vectors.json` (gaps KithMoot's original file
  did not cover, from the T0 vector-review branch), and `fold-vectors.json`
  (this kit's own T3.1/T3.3/#205 vectors, with no KithMoot counterpart - see
  `scripts/generate-fold.mjs`), and `member-epoch-vectors.json` (member
  epoch catch-up, in KithMoot's vector format so it can be copied into
  KithMoot's `vectors/` verbatim - see `scripts/generate-member-epoch.mjs`).
  `vectors/verify.test.ts`, `vectors/verify-circle.test.ts`,
  `vectors/verify-fold.test.ts` and `vectors/verify-member-epoch.test.ts` run this
  kit's own functions against them. `vectors/lib/determinism.mjs` and
  `vectors/lib/fixtures.mjs` are copied from KithMoot unchanged (fixed
  labelled inputs, no KithMoot-specific behaviour).
- `scripts/` - `diff-source.mjs` (proves moved bodies are byte-identical to
  the pinned source, with one declared exception - see EXTRACTION.md "The
  #205 fix"), `generate-fold.mjs` (builds `vectors/fold-vectors.json`),
  `bundle-check.mjs` (browser bundle size and `node:` import check),
  `tarball-smoke.mjs` (real-tarball consumer smoke test).
- `dist/` - build output (generated, not committed).

## Exports

Two entry points, `@forgesworn/fold-kit` and `@forgesworn/fold-kit/lane`.
See README.md for the full list, grouped by area (identity/verification,
kinds/types, rooms/credentials/access, links/invitations, epochs, channel
derivation, lane).

## Coding Conventions

- British English spelling in identifiers and prose: `licence`, `colour`,
  `behaviour`, `organise`
- Every `kithmoot/v*` derivation label and message prefix is a protocol
  name, not branding, and must stay byte-identical to the pinned source
  commit (EXTRACTION.md). A change to one is a wire-format change: it needs
  new vectors, a version bump on the affected envelope, and cannot land as
  an ordinary refactor.
- `src/labels.test.ts` freezes the full set of `kithmoot/` strings this
  kit's `src/` carries. Adding, removing or editing one anywhere fails that
  test until the frozen list is updated deliberately.
- Peer dependencies (`nostr-tools`, `@noble/hashes`, `@noble/curves`), never
  bundled dependencies - a consumer keeps one copy of each, at the same
  versions KithMoot pins. `@noble/hashes` is pinned to `^1.8.0` only (not
  also 2.x): this kit's `@noble/hashes` imports have no `.js` suffix and its
  `hkdf` calls pass a string `info` argument, and 2.x's `exports` map only
  resolves `.js`-suffixed subpaths while its `hkdf` rejects a string `info`
  - so 2.x cannot satisfy these imports as written, unlike `@noble/curves`
  (imported with `.js` suffixes throughout, and pinned to a single major
  anyway).
- Keep `src/` framework-free and silent: no DOM access, storage access,
  environment reads, console output, or baked-in relay defaults.
- Maintain ESM-compatible imports/exports (`.js` extensions on relative
  imports).
- Git: commit messages use `type: description` format. Do not include
  `Co-Authored-By` or other AI-attribution trailers.

## Working Guidelines

- Do not edit generated output in `dist/` by hand.
- A change to a moved module's *behaviour* (not just its home) is a wire
  compatibility question first: check EXTRACTION.md for which KithMoot
  module it came from, and whether KithMoot still carries its own copy of
  the same code (it does today; T2.1, KithMoot's cutover to this kit, is a
  separate, later step - see the extraction plan).
- `evaluateAgentAccess` stayed in KithMoot (`access.ts`) because it needs
  `ownership.ts` and `RosterEntry`, neither of which moved. `ChatLog` and
  the chat event codecs stayed in KithMoot (`chat.ts`); only `deriveChannel`
  moved, into `channel.ts`. The relay pool (`relay-pool.ts`, `relay-auth.ts`,
  `anonymous.ts`) has not moved yet - this kit declares its own
  `RelayTransport` interface in `transport.ts` rather than importing one.
- Update documentation (`README.md`, `llms.txt`) when the public API or
  behaviour changes.

## Release Notes

Pre-1.0. Seeded on npm as `@forgesworn/fold-kit@0.0.0-seed.0` under the
`seed` dist-tag with trusted publishing configured; the real `0.1.0` release
has not been published yet. Until it is, a consumer pins an immutable Git
commit (see README "Install").

Releases go through the shared `forgesworn/anvil` reusable workflow
(`.github/workflows/release.yml`), triggered by a published GitHub Release
or a manual dispatch naming a tag. `.github/workflows/ci.yml` runs
`npm run check` (including `diff-source`, against a checkout of the pinned
KithMoot commit it fetches itself) on Node 22.13 and 24, on every push to
`main` and on every pull request.
