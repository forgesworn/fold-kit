/** Circle-layer wire kinds: a subset of KithMoot's `src/kinds.ts`, copied
 * byte-identical per entry from the pinned source commit (see
 * docs/plans/2026-09-28-circle-kit-extraction.md §1.1 and EXTRACTION.md in
 * this repository). KithMoot's own `kinds.ts` spreads these into its wider
 * `KINDS` object and keeps the rest (roster, signalling, descriptor,
 * pairing, call bell, and so on) itself.
 *
 * `CHAT` (1460) is included because Girnel's board events share KithMoot's
 * chat kind, so a relay cannot tell a board from a chat (plan Decision 3). */
export const KINDS = {
  /** Device credential. Signed by the participant key; never published to a
   *  relay - it travels inside the encrypted roster, so relays never see the
   *  participant pubkey. */
  CREDENTIAL: 20460,
  /** Chat message, encrypted to the room key and published once, exactly
   *  like the roster. Unlike the roster this is a DURABLE kind (regular
   *  event range, not ephemeral) - chat history is the point, so it must
   *  survive a relay restart and be there for late joiners. */
  CHAT: 1460,
  /** A prospective member proving possession of a room invitation.
   *
   * Ephemeral deliberately: it is a live rendezvous with an inviter, not a
   * request a relay should retain. The public `d` tag is derived from the
   * bearer capability; the request body is encrypted under a separate key
   * derived from that capability. */
  INVITATION_REQUEST: 20466,
  /** A delegated responder's encrypted response carrying the room traffic
   * secret and its root-authenticated, room-bound delegation chain. Addressed
   * to the requester's one-use pubkey; knowing the bearer does not let
   * somebody nominate a responder or substitute a room. Ephemeral for the
   * same reason as the request. */
  INVITATION_GRANT: 20467,
  /** A durable, creator-authenticated tombstone for one invitation.
   *
   * Unlike the live request/grant exchange this MUST be a regular stored
   * event: a delegated responder that was offline when the creator rotated
   * the link has to learn that fact before it starts answering the old link
   * again. The invitation id is unique, so one valid retirement is final. */
  INVITATION_RETIREMENT: 1461,
  /** A persistent group's invitation, signed by the pinned inviter and
   * encrypted under a separate bearer-derived key. Regular stored event:
   * newcomers can enter with every member offline. Contains epoch 0 only;
   * it never grants authority to rekey or bypass a later removal. */
  GROUP_INVITATION: 1463,
  /** A room moving to a new epoch: a fresh traffic secret, sealed per
   * remaining device, with the participants removed at this step named.
   *
   * Durable, and addressed by the public room id, so a client can find the
   * room's current epoch from the id alone and know it is behind before it
   * says anything under a key that is dead. The body is encrypted to the
   * previous epoch's key, so a relay sees the room id, the epoch number,
   * the authority's pubkey and a size, and nothing about who was kept or
   * removed. Signed only by the room's authority, the root inviter pinned
   * in the link. See `epoch.ts`. */
  ROOM_REKEY: 1462,
  /** A member that missed a rekey - it was offline, or it is arriving now -
   * asking the authority for the current epoch, proving which participant it
   * speaks for with its device credential. Encrypted to the authority and
   * ephemeral: it is a live handshake, not a record. */
  EPOCH_REQUEST: 20468,
  /** The authority's answer, sealed to the asking device: the current epoch's
   * secret and the removed set, or a refusal. Ephemeral for the same reason. */
  EPOCH_GRANT: 20469,
} as const
