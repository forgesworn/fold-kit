# Quiet automatic replies

Unreleased. A desk that answers automatically, at once, under a key that does
not change, tells anybody who can make it answer when the device holding
that key is online and how quickly it responds. A removed member still holds
the epoch-0 room key, and anybody with a temporary link holds its bearer, so
both can ask as often as they like. This is the timing side channel
described as "Careless Whisper" for silent delivery receipts.

None of what follows changes an event's content, tags or kind, and no
vector changes. It only changes whether a reply is sent, and when.

## The authority desk (`hostRoomEpoch`)

On by default.

- **Every answer waits.** Grants and refusals alike wait a random
  `replyDelayMs` first, default `[500, 2000]` milliseconds
  (`DEFAULT_REPLY_DELAY_MS`). If only refusals waited, the wait itself would
  give the answer away. The desk decides when the wait ends, not when the
  request arrived, so a removal or a rekey during the wait applies. Closing
  the desk cancels every wait. `[0, 0]` answers at once, as before.
- **A refusal goes out once per participant per window.** A `removed` or
  `closed` refusal is sent at most once every `refuseAgainAfter` seconds,
  default 3600 (`REFUSE_AGAIN_AFTER_SECONDS`). An `unknown` refusal is sent
  at most once every `reportUnknownEvery` seconds (default 60, the same
  cadence that already limits `onUnknown`). A request inside the window gets
  no reply, and its asker times out with the plain "not answering" error
  rather than `EpochRefusedError`.
- **Refusals are capped in total.** At most `maxRefusalsPerMinute`
  refusals of any kind go out in any 60 seconds, default 20
  (`MAX_REFUSALS_PER_MINUTE`). Anybody can mint a participant key, so a
  per-participant limit alone would not stop a room-key holder asking as
  somebody new each time.
- **Grants are never limited.** A participant who is granted is forgotten
  by the limiter. Letting an `unknown` participant in still works on their
  next ask, because a grant is never held back.
- **Memory is bounded.** The limiter remembers at most 256 participants
  (`REFUSAL_LIMITER_CAPACITY`) and forgets the oldest first. The
  per-minute cap still holds after that. No more than 256 requests wait at
  once, and a request turned away while the queue is full is answered when
  it is retried.
- `onRefused` and `onUnknown` still fire on the desk for a refusal the
  limits kept off the wire, so an application sees everything it saw
  before.
- `random` and `schedule` can be injected for tests.

## The temporary-link responder (`hostRoomInvitation`)

Off by default. Without the new options, nothing waits, no subscription is
added, and grants are published exactly as before.

- `grantDelayMs: [min, max]` waits a random time in that range before every
  grant, after `admit` when one is set. This is for a device that answers
  without asking anyone.
- `coordinate: true` is for a room where several delegated devices answer
  the same link. Each one waits (`grantDelayMs`, default `[500, 2000]`),
  watches for grants to the same requester (kind 20467, the link's `d` tag,
  the requester's `p` tag) from any other key, and stands down if one
  appears. Normally only one device answers. It cannot read the other
  grant, and does not need to.
- Anyone holding the link could post a false grant, so a responder stands
  down at most once per request. It then forgets the request, so the
  requester's next retry of the same request is answered without asking
  `admit` again.

## The member desk (`hostMemberEpochDesk`)

Unchanged. It already waits a random `[0, jitterMs)` (default 1500 ms),
stands down once per requesting device when another member answers, and
publishes nothing for a refusal (see `docs/member-epoch-catch-up.md`,
"Anti-amplification").

## What this does not hide

A desk that answers at all still shows that some device holding its key is
online at some point in the window. The delay hides how quickly it answers,
and the limits stop a key holder polling it. It does not make the desk's
presence invisible.
