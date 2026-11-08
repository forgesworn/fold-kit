# Existing rooms on a node

This is a protocol capability, not a shipped client migration feature. A client
must supply durable transition storage, authenticated relay I/O, history copying
and readback, and user review before changing a room's route.

The keeper may sign `kithmoot/v1/node-room-existing` using the room's original
root authority and room ID. Unlike `kithmoot/v1/node-room`, it preserves the
room's destruct setting and leaves files to the client's existing policy.
Neither profile grants access by itself. Every device still needs its own
keeper-signed grant for the pinned node. Old readers reject the new profile.

`@forgesworn/fold-kit/node-migration` signs and verifies preparation, per-session
readiness and commitment evidence. Preparations name the exact device and
session pairs to cover: desktop, Android and web are separate endpoints even
when they represent one person in one room. They expire after ten minutes.
Each readiness binds its preparation, node, current device grant and digest of
original signed history IDs. A commitment requires every named endpoint once.
Committed evidence can be recovered after the preparation expires, until the
commitment's own expiry. A digest is an acknowledgement, not independent proof
that a relay stored anything: the client must check publication and readback.

Evidence contains private room, device and grant associations. Transport it
inside the room's authenticated encrypted control channel, never as bare events
on public relays. Room traffic keys, account secrets and authority secrets must
never be sent to the node. Membership, epoch, roster and route checks remain the
embedding's responsibility; these codecs cannot prove a roster was complete or
stop a newer client joining during preparation. Do not enable migration until
those checks and interruption recovery exist in every supported client.

The signed fixtures in `vectors/node-migration-vectors.json` are synthetic.
TypeScript and Android Kotlin independently verify the same wire data. Existing
node-room vectors and legacy links remain unchanged.

The encrypted control transport accepts 2,000 characters per message. Use
`encodeNodeMigrationFrames` and one `NodeMigrationFrameReceiver` per room to
carry larger signed decisions. Each carrier stays below that limit. Bind
reassembly to the outer message's verified **device** key, not the participant
key shared by desktop, Android and web. Reassembly permits out-of-order parts,
bounds pending copies, expires partial assemblies and verifies the complete
wire digest and signature before returning evidence to the decision decoder.
