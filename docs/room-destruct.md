# Self-destructing rooms

Status: 0.9.0. The wire format for KithMoot's room self-destruct: a room
whose devices, when it ends, delete what they wrote and forget the room.
This release adds only the flag and its readers. It deletes nothing itself:
the tidy-up (NIP-09 deletions, blob deletions, local wipe) is the client's.

## The flag

`destruct: true` rides in three places, each one already signed by the
room's authority (the root inviter):

| Event | Where | Encoder | Reader |
|-------|-------|---------|--------|
| Group invitation (1463) | encrypted body, after `ends`, before `relays` | `encodePersistentInvitation({ destruct: true })` | `PersistentRoomAdmission.destruct` |
| Invitation retirement (1461) | plain JSON content, after `ended` | `encodeInvitationRetirement({ ended: true, destruct: true })` | `decodeInvitationRetirementNotice(...).destruct` |
| Closing rekey (1462) | encrypted body, after `closed` | `encodeRekeyEvent({ closed: true, destruct: true })` | `RekeyNotice.destruct`, `RekeyEvidence.destruct` |

Each is `true` or absent. Omitted, or passed as `false`, every event is
byte-identical to 0.8.0's.

### The group invitation

The body order is `v, room, secret, ends, destruct, relays`. `destruct`
without `ends` is valid: a room with no fixed end self-destructs when its
authority closes it.

- **Strict, as `ends` is.** `decodePersistentInvitation` refuses the whole
  envelope (null) when `destruct` is present and not `true`: `false`,
  `"true"`, `1` and `null` are all refused. The encoder never writes them.
- **Never a tag.** The NIP-40 `expiration` tag is unchanged; nothing on the
  outside of the event says the room self-destructs.

### Two signed copies

`requestPersistentRoomAdmission` reads every stored copy of the invitation
before it admits. When two copies disagree on `destruct`, the flag sticks:
any valid copy from the authority that says `destruct` makes the admission
`destruct: true`, whichever order the copies arrive in.

This is the rule `ends` already follows ("the earlier end stands, so a stale
copy can never keep a room open longer"): for a claim that limits the room,
the more limiting copy wins, regardless of timestamp. A stale or careless
copy can never keep a room's content alive. Only `relays` follows
newest-wins, because relays are a routing preference rather than a limit.
The three merge independently: earliest end, sticky destruct, newest relays.

The consequence is that an authority cannot take back a self-destruct by
republishing the invitation without it. It can only close the room.

### The retirement

An ended room's retirement may say the room self-destructs:
`{"v":1,"ended":true,"destruct":true}`.

- **Only beside `ended`.** The encoder throws on `destruct` without `ended`,
  and `decodeInvitationRetirementNotice` reports `destruct` only beside
  `ended: true`. A retirement whose flag is missing, malformed or without
  `ended` is still a valid retirement (a retired link must stay retired); the
  flag is simply not believed.
- **Not encrypted.** Unlike the other two, the retirement's content is plain
  JSON, as `ended` always was. It names no member and links no rooms: the
  event is signed by the inviter key and tagged with the invitation id, which
  nobody without the link can tie to a room. What it does tell a relay is
  that whoever holds this link was in a room that self-destructed, the same
  order of fact `ended` already gives away. A client that does not want even
  that can leave the retirement unflagged: the invitation and the closing
  rekey carry the flag inside the encryption, so members learn it without
  the retirement.
- `retirementError` is unchanged: a joiner is told the room was ended.

### The closing rekey

The body order is `v, epoch, removed, (by), closed, destruct, (scheduled),
(commit), (members), keys`. A closure seals the next secret to nobody, so
`keys` is empty.

- **Only beside `closed`.** The encoder throws on `destruct` without
  `closed`. With `scheduled` it throws twice over: `scheduled` refuses a
  close, and `destruct` needs one.
- **Not believed without it.** `decodeRekeyEvent` and `readRekeyEvidence`
  report `destruct` only when the body says `closed: true`, and only for the
  value `true`. A body that carries the flag on an open rekey (beside a
  removal, or beside the scheduled marker) is still read in full, without
  the flag. Refusing it would leave the device on the old epoch and hide the
  removal, and a 0.8.0 reader reads it anyway, so the readers follow the
  `scheduled` precedent: drop the contradictory flag, keep the rekey.

## Compatibility

Every reader of these three formats, in 0.8.0 and in KithMoot Android's
port, reads named fields off the parsed body and never enumerates its keys,
so an unknown key is ignored. Both directions, for each:

- **New writer, 0.8.0 reader.** The invitation admits with the same secret,
  end and relays and no `destruct`; the retirement reads as `{ ended: true }`;
  the closure reads as an ordinary close. Checked against a real 0.8.0 build
  and recorded per vector as `oldReader`. An old client in a self-destructing
  room ends it the old way and tidies nothing.
- **0.8.0 writer, new reader.** No flag, so `destruct` is absent everywhere.
- **The one tightening.** A 0.9.0 reader refuses a group invitation whose
  `destruct` is present and not `true`. No released writer produces one;
  a 0.8.0 reader admits it (`destruct-invitation-malformed`).
- **Types.** `PersistentRoomAdmission.destruct`, `RekeyNotice.destruct` and
  `RekeyEvidence.destruct` are optional `true`; the retirement notice's type
  is now `{ ended: boolean; destruct?: true }`, which still satisfies
  `retirementError`.

## What this does not cover

- **A device that missed the closure.** A device offline at the close learns
  of it from the authority's epoch refusal (`refused: 'closed'`), which
  carries no flag. A room flagged on its invitation is covered by the stored
  admission. A room first flagged on its closing rekey is covered only for a
  device that reads that rekey (it is stored; `readRekeyEvidence` reads it
  from the previous epoch's key).
- **Deletion itself.** Each device can delete only what it signed, and
  relays may keep copies. The flag is an instruction to cooperating clients.

## Vectors

`vectors/destruct-vectors.json` (generated by `scripts/generate-destruct.mjs`,
checked by `vectors/verify-destruct.test.ts`), one group, `destruct`:

- `destruct-invitation`: a conference invitation with `ends`, `destruct` and
  `relays`; `unflagged` is the same invitation with the same draws and no
  flag, so its body is the flagged body without `"destruct":true,`.
- `destruct-invitation-no-end`: `destruct` with no `ends`.
- `destruct-invitation-malformed`: `false`, `"true"`, `1`, `null`, built by
  hand; each refused, each admitted by the 0.8.0 reader.
- `destruct-invitation-copies`: an older flagged copy and a newer unflagged
  one naming the relays; admitted with `destruct` and the relays in either
  order.
- `destruct-retirement`: `ended` and `destruct`; `unflagged` is 0.8.0's ended
  retirement with the same draw.
- `destruct-retirement-not-ended`: the flag without `ended`, built by hand;
  the encoder refuses it, a reader keeps the retirement and drops the flag.
- `destruct-closure`: a closing rekey with the flag, read by both readers;
  `unflagged` is the same closure with the same draws.
- `destruct-rekey-open`: the flag beside a removal and beside the scheduled
  marker, built by hand; the encoder refuses both, a reader reads both
  without the flag.
