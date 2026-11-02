# Ask-only node rooms, version 6

This opt-in codec is separate from the legacy room-link parser. Versions 2,
3 and 5 keep their existing bytes and meaning. A version 6 link carries a
signed node descriptor and no bearer welcome, traffic secret or TURN token.
An older reader rejects it as an unsupported version. Reading it is not
admission. Host lifecycle, device enrolment and child acknowledgements remain
the application's responsibilities.

Import these APIs from `@forgesworn/fold-kit/node-room`. This separate entry
keeps the existing main-entry browser budget unchanged.

## Node descriptor

`signNodeRoom` writes kind 27542, used as signed private application evidence
in a link or encrypted room channel, never as a relay-published grant. The
content profile is `kithmoot/v1/node-room`. The signer is the pinned room
authority. Its strict body names version 1, room ID, HTTPS node origin and
node service public key, `calls:relay-only`, `files:off` and an optional fixed
room end. The `d` tag matches the room. An end is mirrored in a NIP-40 tag
and is at most 30 days after creation. No end means the room continues until
its authority closes it; it does not remove rolling event expiry.

`readNodeRoom` verifies the uncached signature, shape, origin, policy and
optional authority pin. It derives exactly one `/events` relay, the node's
STUN URL and four TURN URLs: UDP and TCP 3478, TLS 5349, and TLS 443 at
`turn.<node>`. No supplied fallback list is accepted. `encodeNodeRoomLink`
and `parseNodeRoomLink` use the fragment envelope `{v:6,node:<signed event>}`.
The service public key identifies the node transport; it is not an owner,
room authority or admitted device key.

`withNodeRoomExpiration` applies the earlier of 30 days from signing, the
room end and an event's existing expiry. Call it before signing every
node-room event, including events made by rotating and one-time signers.
Legacy rooms do not acquire this policy.

For retained chat and epoch responders, pass an `ExpirationDeadline`
callback to the relevant codec's `expiresAt` option. It is resolved when an
event is signed, so the horizon moves even if the host stays open for more
than 30 days. Fixed numeric ends and absent expiry retain their existing
bytes. A callback error or invalid result stops signing.

## Admission exchange

An asker creates a fresh room device key and a room-scoped participant-signed
device credential. `encodeNodeJoinRequest` verifies that credential and seals
it, an optional sanitised name, a fresh nonce, room ID and descriptor ID to
the room authority. `decodeNodeJoinRequest` verifies the evidence and returns
the request ID, device, participant and credential. It never grants access.
The application must deduplicate requests and apply its admission policy.

The inner messages use kinds 20466 and 20467 and profiles
`kithmoot/v1/node-ask` and `kithmoot/v1/node-answer`. They are unsigned NIP-59
rumours inside sender-signed kind 13 seals, encrypted using NIP-44 v2. A
fresh throwaway key signs each outer kind 1059 gift wrap. Its only tags are
recipient `p` and NIP-40 expiration. Both signatures are checked without
trusting a cached verification flag. The rumour hash and seal author must
agree. Only the intended recipient can open the message. The fresh outer
timestamp and maximum ten-minute lifetime allow bounded, expiring ask-door
storage; this profile does not use NIP-59's random timestamp backdating.

Only the authority can answer. Before calling `encodeNodeJoinAnswer` with
an admission, the application must post the signed device grant to the node
and receive both Spry and Shelter acknowledgements. The encoder verifies the
request, room secret and active node-profile grant. The answer includes the
request ID, descriptor ID, room and device, root room secret, epoch hint and
the signed grant, all sealed to that device. It expires within 90 seconds
and never after the original request. An explicit refusal includes no secret
or grant. No bearer-readable kind 1463 is published.

`decodeNodeJoinAnswer` needs the stored request ID and expiry, device key and
pinned descriptor. It rejects cross-request, cross-room, cross-node,
wrong-device, wrong-authority, tampered and expired evidence. The returned
admission is persistent, self-destructing, has only the node relay, and has
an empty storage-node list. The app must retain the node descriptor, apply
the full grant receiver's ordering/revocation rules, complete epoch admission
and enforce node-only transports and files-off behaviour. A parsed answer is
not evidence of successful relay login or a working call.

## Grant subset and qualification

`signNodeClosure` writes a canonical kind 27543 statement explicitly binding
the room, node host and random close operation. It expires after 30 days.
`readNodeClosure` verifies it; `recoverNodeClosure` reconstructs it from a
compact signature proof and the member's pinned descriptor. That compact proof
contains no raw room ID or public key. A grant reset, access refusal, expired
grant or node signature alone does not authorise deletion on a device.

`readNodeCloseReceipt` verifies a kind 27544 completion receipt signed by the
pinned node service key and bound to the expected operation. Both child
results must be complete. The node's receipt authenticates its assertion;
it does not prove underlying storage-media erasure and does not replace the
keeper's closure statement.

`readNodeOperationReceipt` performs the same receipt verification with only
the paired public service key, expected operation id and current time. After
self-destruct, an owner can poll for completion without retaining a room
descriptor, room id, member list or traffic key. This receipt never authorises
deletion on another device.

Version 6 has no legacy invitation secret. `signNodeRetirement` writes its
kind 1461 retirement using the room authority signature and NIP-44 encryption
under the root room key. Its body is exactly `{v:1, profile:
"kithmoot/v1/node-retirement", descriptor, operation, closed:true}`. The
`d` tag names the room; NIP-40 expiry is the earlier of thirty days and the
signed room end. `readNodeRetirement` verifies the signature and deadline,
then decrypts and checks the descriptor and operation before accepting it. The
application durably submits this event with its closing kind 1462 rekey,
grant reset and explicit kind 27543 statement before retiring the local room.
The explicit statement remains the independently recoverable wipe authority
after relay purge. A retirement event alone is not a substitute for it.

`verifyNodeRoomGrant` accepts the active kind 27541 subset with exactly the
three scopes `turn`, `relay-read` and `relay-write`, the pinned authority,
room, node host, admitted device and a live expiration. It checks signature
and the maximum 90-day grant lifetime. It does not replace a grant ledger:
terminal revocation, reset floors, renewal ordering and protected-key state
must also be checked by the node and clients. GROUP-GRANTS remains the
authority for that protocol.

The deterministic [vectors](../vectors/node-room-vectors.json) record the
descriptor, link, credential, grant, sealed request, admitted answer, refusal,
retirement, closure, receipt and every randomness input. Tests reproduce their exact bytes. Keys in that
file are synthetic fixtures. These are codec checks; web/Android vector
parity, real-node transport, network isolation, signed release dependencies,
physical device acceptance and UI review are separate release gates.
