# Persistent invitation evidence

The additive `requestPersistentRoomAdmissionEvidence` API retains what an
injected stored-event query observed, so protected clients can revalidate the
signed source of a fixed relay list after restart. It performs no publication,
storage or routing effects and supplies no relay defaults. The existing
`requestPersistentRoomAdmission`, encoder, decoder and wire formats are unchanged.
Import from `@forgesworn/fold-kit/persistent-invitation-evidence`; the existing
main entry and its bundle budget remain unchanged.

## A single creator source

`revalidatePersistentInvitationSource({ event, invitation, expectedRoomSecret })`
validates one actual `encodePersistentInvitation` Event, or the exact canonical
carrier string retained from it. The exact 32-byte room-root pin is mandatory;
missing, malformed or mismatching pins fail rather than disabling the check.
The capability and root are copied before carrier verification, and temporary
copies and derived keys are erased. The returned `admission.secret` is a fresh
owned buffer that the caller must erase. Caller buffers are never erased.

`PersistentInvitationSource` is a frozen envelope with `version: 1`,
`invitationId`, `inviter`, `eventId`, `createdAt`, the canonical `event` string
and owned `admission` fields. It authenticates the supported encoder's exact
signature, inviter, invitation ID, root, end/expiration, destruction flag and
relay list. Retirement events and noncanonical reload strings are rejected.
The same plain-data boundary and 16,384-byte carrier limit below apply, with
string bounds checked before parsing and object bounds before verification.

This source has **no completion/EOSE claim**. It is not a query observation,
latest-event selection, publication receipt, current membership authority or
evidence of absence of retirement. A creator retains the canonical event,
actual owner/fixed metadata and a bounded pending publication intent in
acknowledged protected custody before opening any relay pool. After uncertain
delivery it retries these exact event bytes without signing again or changing
the timestamp. Every underlying write still needs a fresh client authority,
generation and lifecycle guard. These storage and effect rules are client
responsibilities; this validator performs no signing, relay I/O or storage.

## Carrier and bounds

`PersistentInvitationEvidence` version 1 contains `invitationId`, `inviter`,
`completion: 'eose'`, sorted unique `eventIds` and corresponding `events`.
Each event string is JSON in this exact field order:
`id, pubkey, created_at, kind, tags, content, sig`. This preserves every signed
field, tag order and ciphertext. It is an allowlisted representation of the
Event supplied by the transport, **not the original relay wire JSON bytes**.
The optional Nostr verification-cache symbol is discarded and never trusted.
Unknown fields, non-data descriptors, custom prototypes, sparse arrays and
noncanonical reload strings are refused. JavaScript proxies are outside this
plain-data transport boundary; callers must not pass executable objects.

Retained evidence holds at most 64 events, with 16,384 UTF-8 bytes per
canonical carrier and 262,144 UTF-8 bytes across all retained carriers. Event
tags are bounded to 64 arrays of at most eight strings. These are
evidence-profile limits, not new wire limits for the legacy API.

A query reads at most 512 deliveries
(`MAX_PERSISTENT_INVITATION_EVIDENCE_DELIVERIES`): every relay's copy of every
event, repeats, other authors and junk alike, each charged before it is parsed.
Past that the query fails, because an event that could matter may be among
those it did not read; delivery 513 is never inspected. The bound limits parse
work only. It is eight times the retained limit so that 64 events heard from
each of eight relays still fit.

What is delivered is then sorted cheaply, before any signature check:

- A malformed or oversized carrier, an event not by the inviter, not kind 1463
  or 1461, or without exactly one `d` tag naming the invitation, is dropped.
  It is not evidence and it does not fail the query.
- An exact repeat, another carrier under an id already held, and a carrier
  already checked and refused, are dropped. A held id was verified, so a second
  carrier with it has the same signed fields.
- Anything else costs one signature check. A query makes at most 128
  (`MAX_PERSISTENT_INVITATION_EVIDENCE_VERIFICATIONS`): room for 64 retained
  events and 64 more in-scope events that fail, forged or not a supported body.
  The 129th is never checked and the query fails.
- A checked, valid authority event is retained. If that would be a 65th event
  or pass 262,144 bytes, the query fails. Nothing is evicted or truncated.

An in-scope, well-formed, validly signed authority event is never dropped. The
failures above are failures, not omissions, and they reject with
`PersistentInvitationEvidenceQueryError`. The one carrier that cannot be kept
is a signed event over the per-event limits above, which no evidence can hold.

Evidence records, carrier strings and ID arrays are frozen owned copies.
String memory is not claimed securely erased. Each admitted result has a fresh
owned secret buffer; callers erase it after use. Temporary decoded secrets,
derived welcome/room keys and the query's invitation-bearer copy are erased.

## Authentication and selection

Both the query and `revalidatePersistentInvitationEvidence` recompute event IDs
and verify signatures without a cached verdict, require the exact inviter and
single two-element invitation `d` tag, and validate capability decryption and
room derivation. Group bodies and tags must exactly match the canonical shape
of the supported encoder, including the exact end/expiration, self-destruct
and relay-list fields. An unknown group body cannot contribute authority.
Authenticated retirements use the existing retirement semantics, including
legacy-valid extended bodies, so stricter group parsing cannot weaken a known
retirement. Every observed valid retirement carrier is retained.

At EOSE the entire retained set is processed in sorted event-ID order:

- Any observed retirement yields `status: 'held', reason: 'retired'`, with
  its event IDs and no admission. No valid group event yields `unavailable`.
- Different decoded room roots yield `conflicting-rooms`. The optional
  `expectedRoomSecret` binds an existing physical room to its exact root;
  a mismatch yields `wrong-room`.
- The earliest end across all signed copies stands. Self-destruct is sticky
  if any copy carries it. A copy without relays makes no relay-list assertion.
- Relay-bearing copies with the greatest `created_at` select the list.
  Different lists at that greatest timestamp yield `conflicting-relays`
  regardless of arrival order; identical lists are accepted. A strictly newer
  list can supersede an older tie. The legacy API still keeps first arrival
  on a tie, preserving existing compatibility.

An admitted outcome exposes `contributors.room`, `.ends`, `.destruct` and
`.relays` as exact event-ID arrays. The aggregate can combine assertions from
several events; it is not represented as a single synthetic signed envelope.
Held results still retain the complete observed evidence for protected refusal
custody and later independent revalidation.

## Completion and failure

The query waits for the transport's EOSE even after an invitation or retirement
arrives. Timeout, abort, subscription failure or a capacity failure (deliveries,
signature checks, retained events or retained bytes) rejects with `PersistentInvitationEvidenceQueryError`.
Its bounded `observation` is explicitly `completion: 'incomplete'`, diagnostic
custody only. The revalidator always refuses incomplete observations. They
cannot be relabelled to establish completeness; completion metadata itself is
local and must be protected by the client's custody transaction.

The query is exact to the two source kinds, inviter and invitation `d` ID.
EOSE binds that local query observation and the listed event identities. It
does not prove that a relay disclosed every retirement or competing event,
global non-retirement, current membership, freshness or current routing
permission. Revalidation after restart proves signed historical consistency
within that retained set. The same room under a rotated invitation has a
different invitation/evidence identity and cannot alias this record.

## Client integration remains required

Clients must retain the exact selected invitation capability and evidence in
protected storage, bind them to the physical room root, and await durable
coherent retention before using decoded fields. A `held` or incomplete result
never grants permission to dial, publish, migrate, clean up or resume admission.
Creator paths must separately prepare and retain the exact signed event with
owner/access bindings, fixed list and publication intent before network effects,
retrying uncertain delivery with the same event. This API does not fabricate
EOSE for a locally prepared event.

Browser/tab coherence, capacity and client/version fences, selected-lane
consent, supported legacy-row reconciliation, startup ordering, current
authority and actual app/physical acceptance remain client integration work.
This additive library API alone does not activate KithMoot protected recovery,
close DG08 or satisfy authentic MLS admission/independent continuity gates.
