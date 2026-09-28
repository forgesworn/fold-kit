# @forgesworn/fold-kit

Circle primitives for private Nostr groups that nobody operates: a room key
per epoch, sealed to each device that stays; link invitations as
capabilities; member removal by rekey; device credentials so a person
approves a device once and it signs from then on.

Fold-kit is being extracted from [KithMoot](https://github.com/forgesworn/kithmoot)
so that other ForgeSworn clients can share one circle model. KithMoot's wire
format does not change: every derivation label and event shape moves
byte-identical and is pinned by known-answer vectors.

**Status: extraction in progress. No published package yet.**

## How it relates to its siblings

- [`covey-kit`](https://github.com/forgesworn/covey-kit): circle state
  derived from a root, latest-wins configuration, per-recipient gift wraps.
- [`roost-kit`](https://github.com/forgesworn/roost-kit): transport for
  private circles (gift wrap, relay fan-out, offline outbox).
- `fold-kit`: symmetric epoch keys with a pinned authority, sealed rekeys and
  link invitations. Suited to high-rate encrypted streams such as chat and
  collaborative documents, where a wrap per recipient per message is too
  costly.

## Licence

MIT
