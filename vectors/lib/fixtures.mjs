// Every fixed input the vectors are built from, in one place, so a value is
// never typed twice and never drifts between `generate.mjs` and
// `verify.test.ts`. Nothing here is random: every key, secret and timestamp
// is either a literal or derived from a fixed label via `determinism.mjs`.

import { getPublicKey } from 'nostr-tools/pure'
import { deriveSecretKey, seed32 } from './determinism.mjs'

export const BASE_URL = 'https://kithmoot.com/j'

// --- Timestamps (all Unix seconds) ------------------------------------
// Reused across groups so the vectors read as one coherent scenario rather
// than unrelated fixtures, and so a reader can sanity-check "expiresAt is
// after createdAt" at a glance.
export const NOW = 1_800_000_000
export const CREDENTIAL_CREATED_AT = 1_799_990_000
export const CREDENTIAL_EXPIRES_AT = NOW + 3600
export const CREDENTIAL_EXPIRES_AT_EXPIRED = NOW - 3600
export const SIGNAL_CREATED_AT = 1_799_995_000
export const KINDRED_EXPIRES_AT = NOW + 3600

/** A kindred proof names the room it admits its holder to, so every proof
 *  vector is minted for a room - and one negative is minted for a different
 *  one. See `KindredProof` in `src/types.ts`. */
export const KINDRED_NONCE_KEN = '11'.repeat(32)
export const KINDRED_NONCE_KITH = '22'.repeat(32)
export const KINDRED_NONCE_KIN = '33'.repeat(32)
export const KINDRED_NONCE_UNTRUSTED = '44'.repeat(32)
export const KINDRED_NONCE_OTHER_ROOM = '55'.repeat(32)

// --- Room secrets --------------------------------------------------------
// Two edge cases (all-zero, all-0xff) plus two "typical" secrets used
// throughout the rest of the vectors so a credential/roster/signal fixture
// can be traced back to a specific, independently checkable room.
export const ROOM_SECRET_ZERO = new Uint8Array(32)
export const ROOM_SECRET_FF = new Uint8Array(32).fill(0xff)
export const ROOM_SECRET_1 = seed32('room-secret-1')
export const ROOM_SECRET_2 = seed32('room-secret-2')

// --- Identities ------------------------------------------------------
// secp256k1 keypairs derived from fixed labels - see `deriveSecretKey`.
export const PARTICIPANT_A_SK = deriveSecretKey('participant-a')
export const PARTICIPANT_A = getPublicKey(PARTICIPANT_A_SK)

/** A second participant, for the pairwise vectors: verification words are
 *  derived from BOTH keys, so one participant is not enough to pin them. */
export const PARTICIPANT_B_SK = deriveSecretKey('participant-b')
export const PARTICIPANT_B = getPublicKey(PARTICIPANT_B_SK)

/** A third, to pin that the words are bound to the pair rather than to the
 *  speaker: A-with-B must not equal A-with-C. */
export const PARTICIPANT_C_SK = deriveSecretKey('participant-c')
export const PARTICIPANT_C = getPublicKey(PARTICIPANT_C_SK)

export const DEVICE_A_SK = deriveSecretKey('device-a')
export const DEVICE_A = getPublicKey(DEVICE_A_SK)

/** Signs a roster event for an entry that names DEVICE_A - i.e. a device
 *  other than the one the credential authorises. */
export const DEVICE_IMPOSTOR_SK = deriveSecretKey('device-impostor')
export const DEVICE_IMPOSTOR = getPublicKey(DEVICE_IMPOSTOR_SK)

/** A room host trusted by the `kith`-gated policy fixtures. */
export const HOST_SK = deriveSecretKey('host-issuer-a')
export const HOST = getPublicKey(HOST_SK)

/** A second, genuine issuer who is simply not on any policy's allow-list. */
export const HOST_UNTRUSTED_SK = deriveSecretKey('host-issuer-untrusted')
export const HOST_UNTRUSTED = getPublicKey(HOST_UNTRUSTED_SK)

/** The guest whose admission the kindred proofs vouch for. */
export const GUEST_SK = deriveSecretKey('kindred-guest')
export const GUEST = getPublicKey(GUEST_SK)

export const SENDER_SK = deriveSecretKey('signal-sender')
export const SENDER = getPublicKey(SENDER_SK)

export const RECIPIENT_SK = deriveSecretKey('signal-recipient')
export const RECIPIENT = getPublicKey(RECIPIENT_SK)

/** Holds a real keypair but is never the addressee of any wrap - stands in
 *  for a relay operator or a third member of the room trying to open a
 *  signal that was not sent to them. */
export const EAVESDROPPER_SK = deriveSecretKey('signal-eavesdropper')

export const EPHEMERAL_SK_OFFER = deriveSecretKey('signal-ephemeral-offer')
export const EPHEMERAL_SK_ICE = deriveSecretKey('signal-ephemeral-ice')

/** Wraps a forged inner event - see `signalWrap/tampered-inner-signature`. */
export const EPHEMERAL_SK_TAMPERED = deriveSecretKey('signal-ephemeral-tampered')

// --- Profile 2 (docs/protocol.md "Profile 2 additions") -------------------
export const EPHEMERAL_SK_P2_OFFER = deriveSecretKey('signal-ephemeral-p2-offer')
export const EPHEMERAL_SK_P2_ICE = deriveSecretKey('signal-ephemeral-p2-ice')
export const EPHEMERAL_SK_P2_ACK = deriveSecretKey('signal-ephemeral-p2-ack')
export const EPHEMERAL_SK_P2_HEALTH = deriveSecretKey('signal-ephemeral-p2-health')
export const EPHEMERAL_SK_P2_SYNC = deriveSecretKey('signal-ephemeral-p2-sync')

/** Two fixed connection instance ids, 16 lower-case hex - see `SignalBody.conn`. */
export const CONN_A = 'a1b2c3d4e5f60718'
export const CONN_B = '0718a1b2c3d4e5f6'

/** A generation-opening offer's fixed slot map: the four roles of
 *  `docs/protocol.md` section 3.1, each exactly once. */
export const SLOTS_FIXTURE = { '0': 'mic', '1': 'camera', '2': 'screen', '3': 'screen-audio' }

/** A batched `ice` signal's candidates - two trickled candidates sent as one. */
export const BATCHED_ICE_FIXTURE = ['candidate:1 1 udp 1 10.0.0.1 1 typ host', 'candidate:2 1 udp 1 10.0.0.2 1 typ host']

// --- Signalling payloads --------------------------------------------
export const SDP_FIXTURE =
  'v=0\r\no=- 1 1 IN IP4 192.168.1.42\r\na=candidate:1 1 udp 2130706431 192.168.1.42 54321 typ host'
export const ICE_FIXTURE = 'candidate:1 1 udp 1 10.0.0.1 1 typ host'

// --- Forwarders and ICE ---------------------------------------------------
// A forwarder is named by a signalling url and, optionally, its own Nostr
// key. It is never named by anything that could carry the room key - see the
// `roomDescriptor` group, whose whole job is to pin that.
export const FORWARDER_A_SK = deriveSecretKey('forwarder-a')
export const FORWARDER_A = getPublicKey(FORWARDER_A_SK)

export const FORWARDER_B_SK = deriveSecretKey('forwarder-b')
export const FORWARDER_B = getPublicKey(FORWARDER_B_SK)

export const FORWARDER_URL_A = 'wss://fwd-a.kithmoot.example/fwd'
export const FORWARDER_URL_B = 'wss://fwd-b.kithmoot.example/fwd'
export const FORWARDER_URL_LOCAL = 'ws://box-under-the-stairs.local:7788'

/** A STUN-only ICE list: no username, no credential, because TURN
 *  credentials are minted per viewer with a TTL rather than shared. */
export const ICE_SERVERS = [{ urls: ['stun:stun.kithmoot.example:3478'] }]

// --- Epochs and removal ---------------------------------------------------
// A room's authority is the root inviter: the only key that may retire a
// link, and the only one whose rekey a member believes. `EPOCH_SECRET_*` are
// the successor secrets a rekey hands out, sealed to one device at a time.
export const AUTHORITY_SK = deriveSecretKey('room-authority')
export const AUTHORITY = getPublicKey(AUTHORITY_SK)

export const EPOCH_SECRET_1 = seed32('epoch-secret-1')
export const EPOCH_SECRET_2 = seed32('epoch-secret-2')

/** The device a rekey keeps, and the device it removes. The kept device is
 *  the one the sealed copy is addressed to; the removed one is named in the
 *  clear inside the ciphertext, because everybody still in the room has to
 *  know who left and the party being removed is not a reader. */
export const KEPT_DEVICE_SK = deriveSecretKey('epoch-kept-device')
export const KEPT_DEVICE = getPublicKey(KEPT_DEVICE_SK)
export const REMOVED_DEVICE_SK = deriveSecretKey('epoch-removed-device')
export const REMOVED_DEVICE = getPublicKey(REMOVED_DEVICE_SK)

export const REKEY_CREATED_AT = 1_799_999_000
export const EPOCH_CREATED_AT = 1_799_999_950

// --- Agent ownership ------------------------------------------------------
// A principal signs, once, that an agent is theirs. Room-independent by
// design, so the same proof rides in every room that agent joins.
export const PRINCIPAL_SK = deriveSecretKey('agent-principal')
export const PRINCIPAL = getPublicKey(PRINCIPAL_SK)
export const AGENT_SK = deriveSecretKey('agent-participant')
export const AGENT = getPublicKey(AGENT_SK)
export const AGENT_DEVICE_SK = deriveSecretKey('agent-device')
export const AGENT_DEVICE = getPublicKey(AGENT_DEVICE_SK)

export const OWNERSHIP_ISSUED_AT = 1_799_900_000
export const OWNERSHIP_EXPIRES_AT = NOW + 86_400
export const OWNERSHIP_EXPIRED_AT = NOW - 1
export const OWNERSHIP_LABEL = 'Ada, my research agent'

// --- Attachments ----------------------------------------------------------
// A Wildbloom share rides with a chat message: the file event's id, where
// the sealed envelope is served, the hash of those exact bytes, and the
// recovery key that opens them. The key is in the room-key ciphertext and
// nowhere else.
export const ATTACHMENT_EVENT_ID = 'a1'.repeat(32)
export const ATTACHMENT_URL = 'https://kithmoot.example/blossom/' + 'b2'.repeat(32)
export const ATTACHMENT_SHA256 = 'b2'.repeat(32)
export const ATTACHMENT_KEY = 'c3'.repeat(32)
export const ATTACHMENT_SALT = seed32('attachment-salt')
export const ATTACHMENT_NONCE_PREFIX = seed32('attachment-nonce-prefix').slice(0, 8)
export const ATTACHMENT_CREATED_AT = 1_799_999_800

// --- The message layer ----------------------------------------------------
// Replies, edits, retractions, mentions, DM invitations and read positions
// all ride as fields of a chat message or as a record signed by the
// participant key. A second device key for participant B, so a thread can
// have two people in it, and one fixed time for the conversation.
export const DEVICE_B_SK = deriveSecretKey('device-b')
export const DEVICE_B = getPublicKey(DEVICE_B_SK)
export const MESSAGE_CREATED_AT = 1_799_999_700
export const READ_POSITION_CREATED_AT = 1_799_999_900
