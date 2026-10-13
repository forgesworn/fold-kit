# Persistent invitation evidence

The additive `requestPersistentRoomAdmissionEvidence` API retains what an
injected stored-event query observed, so protected clients can revalidate the
signed source of a fixed relay list after restart. It performs no publication,
storage or routing effects and supplies no relay defaults. The existing
`requestPersistentRoomAdmission`, encoder, decoder and wire formats are unchanged.
Import from `@forgesworn/fold-kit/persistent-invitation-evidence`; the existing
main entry and its bundle budget remain unchanged.

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

Queries admit at most 64 delivered candidates, including invalid candidates and
duplicates, with 16,384 UTF-8 bytes per canonical carrier and 262,144 UTF-8 bytes
across all delivered canonical candidates. Work/bytes are charged before crypto;
candidate 65 is refused before carrier copying. Retained evidence has the same
limits. Event tags are bounded to 64 arrays of at most eight strings. These are
evidence-profile limits, not new wire limits for the legacy API. Exact duplicates
cost no additional retained capacity but consume query work and byte budget;
the same ID with a different carrier fails the entire query. Capacity is checked
before admitting another candidate, with no eviction or truncated success.
Malformed/oversized object framing fails the query. Well-framed events that
fail signature, capability or scope validation are ignored, never retained.

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
arrives. Timeout, abort, subscription failure, contradictory duplicate or
capacity failure rejects with `PersistentInvitationEvidenceQueryError`.
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
