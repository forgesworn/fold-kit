# Extraction plan excerpt

This kit was extracted from KithMoot under a private planning document that
also covers work outside this repository's scope (a downstream app that
consumes this kit, not itself part of the public KithMoot/fold-kit
ecosystem). This file carries the parts of that plan needed to understand
decisions recorded in this repository's own docs (EXTRACTION.md, AGENTS.md,
source comments), without naming or linking the private document itself.

## Module list and splits (plan §1.1)

Moves to the kit, byte-identical bodies, only import paths changed: `hex`,
`verify`, `identity`, `kinds` (subset), `types` (subset), `credential`,
`room`, `network-hints`, `display-name`, `access` (split), `invitation`,
`persistent-invitation`, `link`, `epoch`, `channel` (one function extracted
from `chat.ts`), `lane`. A `relay` subpath (relay pool, relay auth,
anonymous routing) is a separate, later move once its churn settles.

`access.ts` split: `issueKindredProof`, `evaluateAccess` and the kindred
message move; `evaluateAgentAccess` stays with the app, since it needs
`ownership.ts` and a roster type that did not move.

`chat.ts` split: `deriveChannel` only moves (into the kit's own
`channel.ts`); `ChatLog` and the chat event codecs stay with the app.

## Decisions relevant to this repository

- Board events (a downstream app's own event kind for its own collaborative
  documents) share KithMoot's chat kind (1460) under a scoped `d` tag, so a
  relay cannot tell a board from a chat. This is why the kit's `KINDS`
  registry keeps `CHAT` even though nothing in the kit itself sends chat
  messages - it is there for a downstream app to reuse the same kind
  number, deliberately, rather than mint its own.
- The kit repository is public from the start.
- The relay pool moves to the kit in a later step, after its churn settles.

## Corrections after the source vector review

- The kit's kinds subset must include chat kind 1460 (see the board-events
  decision above).
- `types.ts` imports a `Reachability` type used by roster and media types
  that did not move; the split leaves that type, and everything that
  depends on it, in the app that keeps it.
- The relay transport interface (`RelayTransport`) lives in the module that
  moves later with the relay pool; the kit declares the transport interface
  it needs itself, rather than importing the app's.
- Every module that owns a `kithmoot/` wire string exports a frozen
  `*_LABELS` list; after any future cutover, the app's own label test would
  import the kit's lists rather than re-declare them.

## Peer dependency rationale (plan §3.4)

Until an npm release exists, a consumer pins an exact Git commit. Once
published, `nostr-tools` and the noble libraries are peer dependencies so
a consumer keeps a single copy of each rather than a second one nested
under this kit.
