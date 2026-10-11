# MLS admission v4 evidence codec

Import from `@forgesworn/fold-kit/mls-admission`.

This implements only the pure codec from the independently reviewed
[Vennel design](https://github.com/forgesworn/vennel/blob/e9a90c6ae724138f15b377a0b22d022c56303bc5/docs/2026-10-11-mls-admission-codec-design.md).
No relay I/O, browser admission, box role service, counter storage, vault signing,
MLS Add or Welcome adoption is implemented here. Existing v2/v3 codecs stay
unchanged; a v4 link is a separate three-element array fragment, not a legacy
room traffic secret or an extended legacy link.

`encodeMlsInvitationV4(root, bearer)` encodes a fragment. Supply a fresh valid
root and 32 CSPRNG bytes, retain their custody, and wipe caller copies on settled
termination. `readMlsInvitationV4(fragment)` returns root, invitation id and a
caller-owned bearer copy. Zero bearers and invalid x-only keys are refused;
these checks cannot establish the entropy of a supplied bearer.

All core/proof inputs are canonical compact JSON of the fixed arrays defined
in the design. Nested signed events are seven-field arrays. Outer wire inputs
and outputs are compact JSON NIP-01 **objects**, with exactly seven fields;
field order may vary, but duplicate keys, whitespace and alternate encodings
are refused. Decoders accept strings only, so caller objects, proxies, accessors
and cached-verification markers never cross the wire decoder boundary.

1. Reserve a global durable counter, stable operation and challenge in the
   actual owner before building the request array. Call
   `mlsAdmissionProofTemplatesV4({fragment, core, now})` for the three purpose-bound
   role templates and expected public keys. Settle the account/browser/enrolled
   device signers inside actual custody. No sealed scalar or generic vault
   signer should be exposed to satisfy this API.
2. `encodeMlsAdmissionRequestV4({fragment, core, proofs, requestSecretKey, now})`
   verifies those exact signed proofs, then encrypts with fresh NIP44 randomness
   and signs using the one-operation ephemeral request key.
3. `decodeMlsAdmissionRequestV4({fragment, event, localSecretKey, side, now})`
   independently verifies the request at either endpoint (`side` is `root` or
   `joiner`). Only this decoder issues `VerifiedMlsAdmissionRequest`.
   `readMlsAdmissionRequestV4(handle)` returns immutable core/digest/event-id
   strings for evidence; they cannot rehydrate its nominal identity.
4. Construct the Allow array against that retained request, get its two keeper
   proof templates with `{fragment, core, request, now}`, and settle actual
   keeper account/device consent after exact current saved-room/leaf checks.
   Deny has an empty proof array. Encode with
   `encodeMlsAdmissionAnswerV4({fragment, request, core, proofs, rootSecretKey, now})`.
5. `decodeMlsAdmissionAnswerV4({fragment, request, event, requestSecretKey, now})` returns
   evidence-only `VerifiedAdmissionAnswer`. `readMlsAdmissionAnswerV4(handle)`
   returns decision, core/digest and event ids. There is no constructor,
   registration hook, capability conversion or admission factory.

Verified handles retain only public root/invitation id and protocol evidence,
never the invitation fragment, bearer or direction keys. Supply the fragment
transiently to each answer operation; its root/id must match the retained request.
Decoded owned fragment/bearer bytes are wiped on parse failure and on settled
operation return. Only `readMlsInvitationV4` transfers its successful bearer copy
to the caller. Immutable caller input strings cannot be overwritten by JavaScript.

The engine device is the enrolled Nostr key named in its person credential,
not the MLS leaf's Ed25519 signature key. All signed events are freshly verified;
strict duplicate/tag/decimal/curve/credential checks apply across both roles.
The application must still pass VMLS credential and binding policy, revocation
checks, current clock/custody checks and typed consent.

The application must obtain a fresh authenticated box/Link keeper witness with
conditional keeper revision at the effect boundary, then consume each operation
once in durable storage. This library cannot attest role, currentness, child
revision, route, counter nonreuse, revocation, durable idempotence or saved-room
truth. Root signature correlates the answer; it does not authorise a keeper.
Repeated decoder calls can return fresh evidence handles; this is deliberately
not a durable replay barrier. Same-answer replay must return existing operation
state without repeated effects. Recovery fetches fresh custody/witness evidence
and reconciles the existing operation with `findJoin`, never a second capability.
Hold when the required vault or authoritative conditional service is absent.

All ciphertexts use a 16,384-byte canonical padded wrapper and 21,936-character
NIP44 payload bucket. Timing, carrier, invitation pseudonym/root, ephemeral
request identity, event correlation, relay/network addresses and volume remain
visible. There is no forward-secrecy claim. Do not log raw evidence, account or
group ids, capability bytes or invitation/request secrets.

`vectors/mls-admission-v4.json` uses synthetic public test keys and independent
Node SHA256/HKDF composition, deterministic test-only Schnorr auxiliary bytes
and NIP44 nonces. Production encoders expose no fixed nonce/randomness option.
`npm run generate-mls-admission` deterministically regenerates that file;
normal tests verify its frozen wire bytes without regeneration. Codec vectors
and local tests are not browser, deployed, two-account or phone acceptance.
