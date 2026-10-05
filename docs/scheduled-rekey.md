# Scheduled rekeys and the history window

Status: 0.8.0. The readers and wire format for phase 2a of KithMoot's key
schedule parity plan (`kithmoot/docs/2026-10-04-key-schedule-parity.md`).
This release adds nothing that rekeys on a schedule. It gives clients what
they need to read such a rekey quietly, and to hand a newcomer the room's
last month, before any authority starts rekeying on a timer.

It makes no forward-secrecy claim and erases nothing. `MAX_MEMBER_EPOCH_CHAIN`
stays at 32.

## The problem

Seal keys (`docs/seal-key.md`) heal a copied device only at a rekey, and a
room rekeys only when somebody is removed. A quiet room heals never. The fix
is an authority that turns the key over on a schedule, which raises three
questions that this release answers on the wire:

- **Every rekey is announced.** A client cannot tell a weekly turn of the key
  from a removal, so it would announce one every week.
- **A newcomer reads only the current epoch.** With the key turning weekly,
  somebody joining on a Friday sees nothing said before Monday.
- **No two clients agree on how much history to keep.** KithMoot reads four
  left epochs; with weekly rekeys that is a month, and with removals it is
  less.

## The design

### The marker

A scheduled rekey carries `"scheduled": true` inside its encrypted body
(`encodeRekeyEvent({ scheduled: true })`), between where `closed` and
`commit` would be.

- **Inside the body, not a tag.** A clear tag would tell the relay that
  nobody was removed. The body is part of the content the event id hashes
  (NIP-01), so the marker is signed.
- **Never beside a removal or a close.** The encoder throws when `scheduled`
  is combined with a non-empty `removed` or with `closed`. A rekey that
  removes somebody is never quiet.
- **Not believed beside one either.** `decodeRekeyEvent` reports
  `RekeyNotice.scheduled` and `readRekeyEvidence` reports
  `RekeyEvidence.scheduled` only when `removed` is empty and the rekey does
  not close the room. A body that contradicts itself is read as a removal or
  a close, so it is still announced.
- **Byte-identical without it.** A rekey with no marker, or with `scheduled:
  false`, is exactly 0.7.0's.

A scheduled rekey is otherwise an ordinary rekey: it carries the commitment
and the member list when asked, so a member grant's chain runs through it
unbroken (`vectors/schedule-vectors.json`, `scheduled-rekey`).

### The history window

`HISTORY_WINDOW_SECONDS` is 30 days, as long as a chat log keeps a message.
`MAX_HISTORY_EPOCHS` is 16. `epochsInWindow(left, now)` is the one rule
every client applies:

- it keeps the epochs left within the window (one left exactly 30 days ago
  is kept, one a second older is not);
- newest first by epoch number, the first given of a doubled epoch;
- at most 16, however many fall inside the window;
- it is pure and never throws: an entry with no usable number or time is
  dropped.

A weekly schedule puts about five epochs in the window; removals push it
higher, and the cap bounds the relay filters a client opens.
`MAX_HISTORY_EPOCHS` (how far back a member reads) is a different limit from
`MAX_MEMBER_EPOCH_CHAIN` (how far behind a member desk will bring somebody).

### The grant carries the window

The authority's grant (kind 20469) gains an optional `passed`: the window's
left epochs, oldest first, each `{ epoch, secret (base64url), left (unix
seconds) }`.

- **Every grant carries it.** An epoch request does not say which epoch the
  device holds, so the desk cannot tell a newcomer from a device coming back.
  Both are given the window. `hostRoomEpoch({ past })` asks for the room's
  left epochs (`LeftEpoch`: `{ epoch, secret, leftAt }`) on every grant.
- **Never epoch 0.** Its secret is the room secret, which the requester
  already holds and which is never handed over. Nothing at or above the
  granted epoch is carried either.
- **The encoder is strict.** `encodeEpochGrant({ passed })` sorts the list
  and throws on more than 16 entries, epoch 0, an epoch not below the one
  granted, a doubled epoch, a secret that is not 32 bytes, or a `leftAt`
  that is not a non-negative integer. An empty or absent list writes nothing,
  so the body is 0.7.0's.
- **The desk is forgiving.** Before encoding, `hostRoomEpoch` drops whatever
  the encoder would refuse and applies `epochsInWindow`, so a bad `past()`
  (or one that throws) costs the history and never the grant.
- **The reader is strict and forgiving at once.** `decodeEpochGrant` takes
  `passed` only in exactly the form the encoder writes (strictly increasing,
  each in `[1, epoch)`, at most 16, 32-byte secrets, a non-negative integer
  `left`), and returns it as `EpochGrant.passed` with `leftAt`. Anything else
  drops the field and keeps the grant: the current epoch still stands.

`decodeMemberEpochGrant` now sets `leftAt` on each passed epoch too, from the
`created_at` of the authority's rekey out of it, so both kinds of answer say
when each epoch was left.

## Compatibility

Both directions, for each change:

- **New writer, old reader (rekey).** 0.7.0's `decodeRekeyEvent` and
  `readRekeyEvidence` build their result from named fields, so they ignore
  the marker. An old client announces a scheduled rekey as it would any
  other.
- **Old writer, new reader (rekey).** No marker, so `scheduled` is absent and
  the rekey is announced as before.
- **New writer, old reader (grant).** 0.7.0's `decodeEpochGrant` reads named
  fields and gets the current epoch, as from any grant before
  (`epoch-grant-window-old-reader`). It reads the window once it updates.
- **Old writer, new reader (grant).** No `passed`, so `EpochGrant.passed` is
  absent, as before.
- **Types.** `EpochGrant.passed` and `MemberEpochGrant.passed` are now
  `Array<RoomEpoch & { leftAt?: number }>`, which still accepts a plain
  `RoomEpoch[]`. `RekeyNotice.scheduled` and `RekeyEvidence.scheduled` are
  optional and absent unless set.

## Vectors

`vectors/schedule-vectors.json` (generated by `scripts/generate-schedule.mjs`,
checked by `vectors/verify-schedule.test.ts`), one group, `schedule`:

- `scheduled-rekey`: empty `removed`, the member list carried, the commitment
  present, the marker present; read as scheduled with its secret, and read
  through `readRekeyEvidence` from the previous epoch. `unflagged` is the
  same rekey with the same draws and no marker: its body is the scheduled
  body without `"scheduled":true,`.
- `scheduled-rekey-contradictory`: the marker beside a removal and beside a
  close, built by hand; both read as not scheduled, and the encoder refuses
  both.
- `epoch-grant-window`: a grant of epoch 18 carrying epochs 2 to 17, the cap.
  The encoder refuses a 17th; a hand-built grant with 17 entries, one with
  two out of order, and one carrying epoch 0 each read as the grant without
  `passed`.
- `epoch-grant-window-old-reader`: the same grant read as 0.7.0 reads it: the
  current epoch only.
- `history-window`: `epochsInWindow` at the 30-day edge, at the cap of 16, on
  a weekly schedule, on unsorted input with a doubled epoch, and on nothing.
