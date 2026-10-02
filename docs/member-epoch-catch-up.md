# Member epoch catch-up

Status: implemented in `src/epoch-commit.ts`, `src/member-epoch.ts` and two
optional additions to `src/epoch.ts`. Unreleased. Vectors:
`vectors/member-epoch-vectors.json`.

## The problem

Only the room's authority (the root inviter key, or a keeper hosting
`hostRoomEpoch` with that key) answers an epoch request (kind 20468, answered
with 20469). Requests are ephemeral, so a device that missed a rekey can
recover only while the authority's device is online with the room open.

What happened on 2 October 2026: room "The moot" was at epoch 1 and its
creating phone was offline. A member's phone had rejoined with a new device
key. Stored rekeys seal only to the devices that were present, so none of
them sealed to the new key, and the phone stayed at epoch 0. Call bells
(keyed per epoch), chat and presence silently stopped crossing between
devices at epoch 0 and devices at epoch 1. A desktop online at epoch 1 held
the secret the phone needed, and nothing let it pass that secret on in a
form the phone could check.

## What the existing format already proves, and the one gap

A rekey into epoch j+1 (kind 1462) is signed by the authority. Its content
is NIP-44 v2 under epoch j's key, and NIP-44's HMAC verifies under no other
key. So a third party holding a candidate secret for epoch j can derive
`deriveEpoch(j, secret).key`, decrypt the authority-signed rekey j+1 and
learn whether the candidate is genuine. **Every epoch that has a successor
is therefore already committed to by an authority signature.**

The current epoch N has no successor. Rekey N refers to secret N only
through its per-device seals (NIP-44 between the authority and each kept
device). Only the authority and that one device can open a seal. So the
existing protocol cannot prove secret N to anybody else, and a member's
answer for the top epoch cannot be checked. That gap is the reason for the
one wire addition below. The rest of the scheme is the existing rekey
chain, read in a new way.

Alternatives considered and not built:

- *A member reveals its NIP-44 conversation key with the authority* so the
  requester can open the member's own seal in rekey N. This is ruled out
  because that key also opens every future seal to that device. A requester
  removed later could read the next secret through it, which defeats
  removal.
- *A member reveals only the per-message NIP-44 keys of its own seal in
  rekey N* (the HKDF-expand output for that seal's nonce). This would work
  for legacy rooms today, and it reveals nothing beyond that one message.
  It was left out because it needs a raw ChaCha20 primitive that this kit
  does not take as a peer dependency, and it works only for a member whose
  device was sealed to at N. A member that caught up through a grant has no
  seal to open. It remains an option if legacy rooms turn out to matter
  more than the remedy below.

## Wire additions

All of these are additive. No existing event changes byte-for-byte unless a
caller opts in, and no existing body version changes.

### 1. The epoch commitment (inside the rekey body)

```
commit = hex( HMAC-SHA256( key = secret_N,
                           msg = "kithmoot/v1/epoch-commit:" + roomId + ":" + N ) )
```

`roomId` is lower-case hex and `N` is decimal. `encodeRekeyEvent({ commit:
true })` writes it into the encrypted body after `by` and `closed` and
before `keys`. The body stays `v: 1`: a reader from before this change
ignores the key, and the label carries the version. It sits inside the
ciphertext rather than in a tag, so a relay still sees only the room id,
the epoch number, the authority and a size. The commitment is used nowhere
else on the wire. A removed member who reads rekey N (it holds key N-1)
learns a PRF output of secret N, which gives it nothing to locate epoch N
traffic with. The epoch id would have done that, which is why the
commitment is not the epoch id.

Without `commit`, `encodeRekeyEvent` produces exactly the 0.4.0 event (the
`roomEpoch/rekey` vector still reproduces byte for byte).

### 2. Member epoch request, kind 20471 (ephemeral)

- Tags: `["d", roomId]`, plus the NIP-40 `expiration` of a conference room.
  It has no `p` tag because no single answerer is addressed.
- Signed by the asking device.
- Content: NIP-44 v2 with the conversation key
  `HKDF-SHA256(roomKey₀, info = "kithmoot/v1/member-epoch-request-key", 32)`,
  where `roomKey₀` is the epoch-0 room key.
- Body: `{"v":1,"credential":<device credential>,"proof"?:<kindred proof>,
  "admission":<epochRequestAdmission(...)>,"have":<the asker's epoch>}`. The
  admission proof is the existing one, binding room, authority, device and
  `created_at`. Members hold `roomKey₀` and check it exactly as the
  authority's desk does.
- Each retry is a fresh event with a new id (see "Anti-amplification").

### 3. Member epoch grant, kind 20472 (ephemeral)

- Tags: `["d", roomId]`, `["p", asking device]`, plus `expiration`.
- Signed by the answering member's **device** key, and NIP-44 v2 to the
  asking device, as the authority's grant is.
- Body: `{"v":1,"request":<request id>,"epoch":N,"secrets":[base64url secret
  for have+1 .. N],"rekeys":[the authority's kind-1462 events for have+1 ..
  N]}`. One grant carries at most 32 epochs (`MAX_MEMBER_EPOCH_CHAIN`).

There is no member refusal event. A refusal from a member is a claim the
requester cannot check, so members decline by not answering. Only the
authority's 20469 refusal means anything.

## Verification rules (requester, `decodeMemberEpochGrant`)

The requester is at epoch `k` and holds key `k`. It accepts a grant only if
all of these hold:

1. The kind is 20472, the signature is valid, the event is fresh (within 90
   s), `d` is the room, `p` is this device, and the body opens with this
   device's key. `request` is one of this device's own outstanding member
   request ids.
2. `secrets` and `rekeys` have the same length L, with 1 <= L <= 32, and
   `epoch = k + L`.
3. If the requester has seen a valid rekey up to epoch E (`expected`, from
   `peekRekeyEvent` on what the relays replay), then `epoch >= E`. This
   blocks a rollback: a member removed at E still holds secret E-1 and could
   otherwise keep the requester one epoch back on a key it shares.
4. For each j = k+1 .. N, in order:
   - `peekRekeyEvent(rekeys[j])` returns j. That means kind 1462, the
     authority's signature, this room and an epoch tag of j.
   - `rekeys[j]` decrypts under key j-1. For j = k+1 that is the
     requester's own key. Later ones derive from the offered secret j-1. A
     decryption failure means the offered secret j-1 is not the one the
     authority encrypted under, and the grant is refused. **This is what
     proves every secret except the last.**
   - The body is `v: 1` with `epoch: j`. If it is `closed`, refuse. If its
     `removed` names the requester's participant, refuse. Otherwise its
     removals are added to the cumulative set.
   - At j = N the body must carry `commit`, equal to
     `epochCommitment(roomId, N, secret N)`. If it is absent, refuse: that
     is a legacy epoch, and only the authority can hand it on. **This is
     what proves the last secret.**
5. Result: `{ epoch: { epoch: N, secret: secret N }, removed: known ∪ every
   removal in the chain, from: member device }`. `removed` is cumulative,
   with the same meaning as the authority grant's.

The answering member's identity plays no part in correctness. The trust
root is the authority's signatures plus the key-committing NIP-44 MAC and
the commitment. A member, a relay or a stranger can withhold an answer.
None of them can make a requester accept a secret the authority did not
issue, an epoch it did not sign, or a removed list it did not write.

The first grant that passes all of these wins (`memberEpochSource` stops on
it). `requestRoomEpoch({ members })` races it against the authority's grant
and settles on whichever verifies first. An authority refusal still
rejects the call.

## Desk rules (`hostMemberEpochDesk`)

A member answers a request only when all of these hold:

- the request decodes: fresh, credentialled for this room, with a valid
  admission proof under `roomKey₀`, and passing the room policy if one is
  given;
- the room is not closed (`closed()`). Otherwise it calls
  `onRefused('closed')` and stays silent;
- the requester's participant is not in this member's cumulative removed
  set, which it learnt from the authority's rekeys. Otherwise it calls
  `onRefused('removed')` and stays silent;
- this device is in step (`current()` is defined) and ahead of `have`;
- it holds every secret and every authority rekey from `have + 1` to its
  own epoch (`secretAt`, `rekeyAt`), and the chain is no more than 32 long;
- when it can read the last rekey itself (it holds the key before it), that
  rekey carries a commitment. A member that joined at the current epoch
  cannot check this, so it sends the grant and the requester decides;
- the serialised grant fits its byte budget (`maxGrantBytes`, default
  60000, under the 64 KiB many relays enforce). The grant inlines whole
  rekey events, each with one seal per kept device, so a long chain in a
  large room can outgrow a relay's limit, and such a chain is left to the
  authority. The requester can already fetch the durable 1462s from its
  relays, so a later revision could carry rekey ids in place of the events.

The requester re-checks everything, so a desk bug cannot weaken anything.
At worst it costs bandwidth.

## Anti-amplification

- Each desk waits a random `[0, jitterMs)` (default 1500 ms) before
  answering.
- If, during that wait, it sees another device's 20472 addressed to the same
  requester, it stands down. It cannot read that grant and does not need
  to.
- It stands down **at most once per requesting device**. The requester sends
  a fresh request every `retryMs` (default 4000 ms, a new id each time)
  until something verifies, and on the second round every desk answers. A
  stranger who posts junk 20472s to suppress honest answers therefore buys
  one round's delay, not a denial of service.
- Requests are deduplicated by id, and each desk answers a given request at
  most once.

## Threat model, and why confidentiality is not weakened

What this protects is the epoch secret: the roster, chat, presence, call
bells and media keys of an epoch. The parties involved are:

- **A current member** already holds secret N and can leak it to anyone.
  Handing it to an admitted, non-removed device gives that device nothing a
  malicious member could not give it anyway. The member path adds no
  capability an insider lacks.
- **A removed member** is refused twice: by every honest desk (its removed
  set comes from authority-signed rekeys), and by the requester's own
  check, which refuses any chain that names it as removed. Its old link
  still opens epoch 0, as it always did. With that it can read member
  requests (sealed under a key derived from `roomKey₀`) and learn the
  credential (participant and device) of a device asking to catch up. That
  is the same in-room exposure a roster at epoch 0 always had, and it is
  stated here rather than hidden. It cannot answer convincingly beyond the
  epoch before its removal, and rule 3 refuses that answer once the
  requester has seen the later rekey.
- **A closed room stays closed.** A closing rekey seals to nobody, so nobody
  holds a secret past it. Desks refuse, and a chain containing `closed` is
  refused.
- **A stranger** with the room id and the authority pubkey from a public
  rekey cannot read a member request (no `roomKey₀`), cannot produce an
  admission proof, and is never answered.
- **A relay** sees, per request, the room id, the asking device's pubkey and
  a time. The existing 20468 already shows it exactly that, plus the
  authority's pubkey in `p`. Per grant it sees the room id, the asking
  device and the answering device. The last of these is new: it shows that
  two device keys are in the same room, which the roster's own publication
  pattern already shows to a relay that watches it. Grant contents are
  NIP-44 to the requester's device, as the authority's grant is.
- **Forgery.** Without the authority's key, nobody can mint a rekey that
  passes `peekRekeyEvent`. Without the real key j-1, nobody can find another
  secret under which an authority-signed ciphertext decrypts (NIP-44's MAC
  is HMAC-SHA256). Without inverting HMAC, nobody can find another secret
  matching the commitment.

What is weakened: nothing about confidentiality. The availability the
authority's absence used to deny is what is restored.

## Legacy rooms (rekeys written before `commit`)

- A legacy rekey **in the middle** of a chain is fine: the next rekey's
  decryption vouches for its secret.
- A legacy rekey **at the top** cannot be vouched for by a member.
  Requesters refuse such grants, and desks that can see the missing
  commitment do not send them. The epoch stays authority-only, exactly as
  today.
- Remedy for such a room ("The moot"): once the authority's device runs a
  version that writes `commit`, a single turnover rekey (no removals) makes
  the whole history member-recoverable. The new top carries a commitment,
  and every earlier epoch, legacy or not, is proven by its successor. Until
  then the room behaves as it does today, and the authority path is
  untouched.

## API

- `epochCommitment(roomId, epoch, secret)`, `EPOCH_COMMIT_PREFIX`
- `encodeRekeyEvent({ ..., commit: true })`
- `readRekeyEvidence(event, { roomId, authority, previous })` reads a rekey
  with the key of the epoch it leaves, with no seal needed: `{ epoch,
  removed, closed, commit? }`
- `encodeMemberEpochRequest` / `decodeMemberEpochRequest`,
  `deriveMemberEpochRequestKey`
- `encodeMemberEpochGrant` / `decodeMemberEpochGrant`
- `hostMemberEpochDesk(opts)` is the answering side
- `memberEpochSource(opts)`, used as `requestRoomEpoch({ members })`, and
  `requestMemberEpoch(opts)` are the asking side
- `MEMBER_EPOCH_KINDS` (`{ REQUEST: 20471, GRANT: 20472 }`),
  `MAX_MEMBER_EPOCH_CHAIN`
