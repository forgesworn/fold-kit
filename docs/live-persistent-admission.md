# Live persistent admission, version 1

This profile lets a first-time device obtain a persistent room's signed
invitation without claiming that a mesh cache contains complete history. It is
a new, opt-in exchange. Existing v3 stored invitations, legacy live delegation,
and the epoch desk are unchanged. The codecs alone do not enable offline joining.

## Authority and the remaining gate

Only the root inviter pinned by the original persistent link may answer. The
answer supplies the existing signed kind 1463 envelope and a current epoch hint;
it supplies no delegation, inviter key or current epoch secret. A delegate or
cache cannot assert that an invitation has not been retired.

Before making an answer, the host must recover its durable invitation lifecycle
and room epoch state, including pending writes, retirement, closure, earliest
room end and sticky self-destruct policy. It serialises the final state check,
answer construction and handoff with retirement, rekey and closure. An old
export or a keeper file without lifecycle evidence cannot become ready merely
because it contains the root key. A host with unknown, pending, corrupt, retired,
closed or expired state refuses. Key possession alone is insufficient.

The existing keeper v2 file does not record a complete invitation lifecycle or
an atomic pending transition. Host integration therefore needs a versioned
durable journal before enabling this profile across a cold start. Older state
must not be silently interpreted as proof of an active invitation. Multiple
independently writable copies of a root key cannot provide global freshness
while partitioned; this profile requires one logical authority writer with
exclusive durable ownership. Restoring an old backup needs explicit recovery.

A verified answer is evidence of the root's state at the time it was signed,
not a lease guaranteeing the room cannot change afterwards. Retirement learned
locally always wins, even over a newer answer. A response already in transit
cannot be recalled. A copied bearer/envelope already reveals epoch zero;
retirement cannot erase it. No offline protocol defeats a lying root or hidden
revocation indefinitely.

After the exchange the client must run an authenticated, current epoch desk
exchange **even for an epoch-zero hint**, before roster, chat or forwarding.
The current client's settle delay / expected-epoch fast path is insufficient
for this entry mode. A hint is a minimum recovery target, never a current-key
grant. An unknown participant stays pending for the existing admission decision;
the new challenge must not call `letIn` from an unproved name or participant key.
Removal, access policy and device credential checks remain the epoch desk's job.
The client stays non-publishing if this gate cannot finish. Rekey racing the
gate retains the room's existing authenticated transition rules and limitations.

## Routing descriptor

The original invitation URL remains intact. Alongside it carry a separate
base64url-without-padding UTF-8 JSON descriptor, at most 512 encoded characters:

```json
{"v":1,"room":"<root room id>","invitation":"<derived invitation id>","inviter":"<pinned root public key>"}
```

All three values are 64 lowercase hex characters. These are the only fields.
Encoders use the displayed order without whitespace. Decoders accept JSON field
order differences but require minified JSON that round-trips through JSON.stringify
without changes. They refuse duplicate fields, whitespace, unknown fields,
non-canonical base64url and wrong invitation/authority. The decoded JSON is at
most 384 bytes. The expected room is checked again against the authenticated
response and the decrypted kind 1463 envelope. A modified descriptor can deny
discovery but cannot substitute a room. Derive the existing nearby scope/UUID
from this root room ID; never advertise the bearer or original URL. The room ID
and persistent discovery scope reveal correlation. This descriptor is routing
metadata, not admission evidence. A client must select Nearby before parsing it
into any transport; signed relay hints never override that route.

The first implementation exposes the descriptor separately; it does not invent
a new universal-link envelope that an old app might open through the internet.
App QR/share integration must preserve the original link and explicit route.

## Wire exchange

Reuse ephemeral kinds 20466 / 20467 with a distinct encrypted profile. This
allocates no MeshCore data type. No public relay publication is required.
Integers are nonnegative safe integers; timestamps are Unix seconds. All hex
fields are lowercase. Signatures are checked without trusting cached verdicts.
Tags contain exactly one two-element `d`, `p` and `expiration`, no others;
ordering does not matter to readers. Writers emit that order.

The requester generates a fresh one-use secp256k1 key and signs kind 20466.
`d` is the existing bearer-derived invitation ID, `p` the root inviter,
`expiration` is `created_at + 90` as canonical decimal. Its NIP-44 v2 plaintext:

```json
{"v":1,"profile":"persistent-live","room":"<expected root room id>","requester":"<event pubkey>"}
```

The symmetric request key is HKDF-SHA256(bearer, empty salt,
`kithmoot/v1/persistent-live/request-key`, 32). The body has exactly these fields, in minified JSON that round-trips through
JSON.stringify without changes (field order may differ). The same rule applies
to the response body, rejecting duplicate fields and ambiguous number spellings.
An event ID binds all request fields and acts as the challenge identifier.
Retries use that same event; a new user attempt uses a new key and randomness.
The host rejects a request over 90 seconds old, more than five seconds in the
future, or at/after its expiry. Legacy request decoders use another key and
cannot treat this request as a delegation request.

The root signs kind 20467, addressed by the same `d` and the requester's `p`.
Its expiry is `min(request.expiration, response.created_at + 30)`. Its NIP-44
conversation key is derived from the root secret and requester public key.
Plaintext, with exactly these fields:

```json
{"v":1,"profile":"persistent-live","request":"<request event id>","room":"<expected root room id>","epoch":0,"invitation":{}}
```

`invitation` is the complete existing signed kind 1463 event, with exactly its
seven wire fields (`id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`).
Do not re-sign it merely to answer a retry. The response's `epoch` is the host's
current nonnegative safe integer epoch, separately returned as `epochHint`;
the decoded persistent invitation still opens epoch zero.

The requester validates its original live request, matches its private reply
key, verifies the pinned root signature, exact tags and expiry, decrypts, and
checks the exact request ID, profile, room and bounded embedded event. The
response may be at most five seconds earlier than the request (clock skew),
at most five seconds ahead of local time, and must not be expired. Its expiry
must equal the formula above. The signed invitation must decrypt under the
original bearer, name the expected room, and be neither future-dated beyond
five seconds nor ended. End/relay/self-destruct semantics are unchanged.
No malformed response escapes as an exception or supplies another authority.

Legacy v2 grants, delegated responses, cached kind 1463 alone, another request's
answer, and an answer from an earlier attempt cannot satisfy this exchange.
The decoder is stateless: the request owner must consume success at most once,
remove its subscription and delete the ephemeral key on success, cancel or
timeout. Do not persist reply keys for restarting a challenge.

## Resource and transport limits

Before cryptography, bound request content to 2,048 characters and complete
request JSON to 4,096 UTF-8 bytes; response content to 16,384 characters and
complete response JSON to 20,480 bytes. An embedded invitation is at most 8,192
UTF-8 bytes, content at most 6,144 characters, eight tags, four strings per tag,
each at most 256 characters. Bound complete raw input before parsing JSON;
`parseLivePersistentEvent` provides that raw boundary and requires minified JSON
without duplicate fields. Typed-event decoders can only bound the already
allocated event object they receive.
Refuse oversize envelopes instead of trimming relay policy or authority fields.

The exchange owner allows one outstanding challenge per device/room, a
90-second monotonic deadline, and at most three identical offers at 0, 30 and
60 seconds. Wall-clock rollback cancels it; time changes never extend the
monotonic deadline. Silence is unavailable, not admission or an automatic
internet fallback. There is no cache-complete/EOSE substitute.

The responder deduplicates at most 128 request IDs for their remaining lifetime
and stores at most one signed reply per accepted request. Admission refuses at
capacity instead of evicting live guards. Each retry rechecks lifecycle state
and expiry before reoffering identical bytes. No re-sign on expiry. Global
limits precede per-peer limits because fresh requester keys are cheap: at most
16 accepted challenges and 64 KiB of reply offers per rolling minute per
authority process, divided among at most eight active rooms. Limit pre-crypto
input work too. A process restart must not reset these budgets. The authority's
durable control ledger is separate from any radio airtime ledger.

These are application bounds, not LoRa duty-cycle compliance. A radio route
must reserve its own airtime and fragmentation budget and can decline a large
reply. BLE qualification comes first. Native text-channel bridging continues
to use its separate gateway identity and trust boundary. Ordinary mixed room
transport does not forward these control messages automatically. A later
transit owner must opt in to exact request/response selectors, directions,
deadlines and quotas; no wildcard control forwarding.

## Implementation and acceptance gates

1. Independent TypeScript/Kotlin codecs and frozen deterministic wire vectors:
   request and response bytes, descriptor, wrong bearer/root/room/request/key,
   duplicate/extra tags and JSON fields, version/profile confusion, stale/future
   times, malformed expiry, end/destruct/relay policy, oversized nested objects
   and forged verification-cache flags. Preserve all existing protocol vectors.
2. Request lifecycle with real mesh transport: all initial packets lost, retry,
   cancel, no peers, last-moment response, clock rollback, process death,
   duplicate answer and zero fallback sockets.
3. Durable authority owner and exact retirement/closure/rekey transaction:
   SIGKILL before/after persistence and handoff, old state migration refusal,
   competing root owners, corrupt storage and requester-rotation floods.
4. Actual fresh RoomSession admission and encrypted chat over mesh, with the
   mandatory authenticated epoch gate and existing unknown/removed policy.
   No delegation appears and no pre-gate roster/chat leaves. Repeat after both
   parties cold-start, and with explicit mixed-path forwarding.
5. Native permission/route/share UI, offline network isolation and physical BLE
   qualification. LoRa measurements and original radio restrictions remain
   independent gates. Codec/vector success must never be labelled a completed
   offline joining or radio result.
