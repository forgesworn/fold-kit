// Public entry point. See README.md for an API overview and EXTRACTION.md
// for where each export came from.

export { hexEquals, normaliseHex } from './hex.js'
export { verifyEventUncached, boundedEventVerifier } from './verify.js'
export type { UnsignedEvent, ParticipantIdentity } from './identity.js'
export { localIdentity } from './identity.js'

export { KINDS } from './kinds.js'
export type { DeviceCredential, AccessTier, AgentRule, RoomPolicy, KindredProof } from './types.js'

export type { RelayTransport } from './transport.js'

export {
  createDeviceCredential,
  verifyDeviceCredential,
  PERSON_CREDENTIAL_MAX_SECONDS,
  RestampedCredentialExpiryError,
} from './credential.js'
export type { CreateCredentialOptions, VerifyResult } from './credential.js'

export {
  SEAL_TAG,
  isSealPubkey,
  generateSealKey,
  credentialSeal,
  sealTarget,
  sealTo,
  openSealed,
  newerCredential,
} from './seal.js'
export type { SealKey } from './seal.js'

export { deriveScoped, SCOPED_LABEL_PATTERN } from './scoped.js'
export type { ScopedKeys } from './scoped.js'

export {
  createSubKeyCertificate,
  verifySubKeyCertificate,
  SUB_KEY_CERTIFICATE_SCOPE,
} from './sub-cert.js'
export type {
  CreateSubKeyCertificateOptions,
  VerifySubKeyCertificateOptions,
  VerifySubKeyCertificateResult,
} from './sub-cert.js'

export {
  generateRoomSecret,
  deriveRoom,
  encodeJoinUrl,
  decodeJoinUrl,
  parseRoomPolicy,
  ROOM_LABELS,
} from './room.js'

export {
  MAX_RELAY_HINTS,
  MAX_ICE_HINTS,
  MAX_NETWORK_HINT_LENGTH,
  isSafeRelayUrl,
  safeRelayUrls,
  isSafeIceUrl,
  safeIceUrls,
  assertNetworkHintBounds,
} from './network-hints.js'

export { sanitiseDisplayName, MAX_DISPLAY_NAME_LENGTH } from './display-name.js'

export {
  issueKindredProof,
  evaluateAccess,
  ACCESS_LABELS,
} from './access.js'
export type { IssueKindredProofOptions } from './access.js'

export {
  INVITATION_DELEGATION_TTL_SECONDS,
  MAX_INVITATION_DELEGATION_DEPTH,
  createRoomInvitation,
  roomInvitation,
  deriveInvitationId,
  encodeInvitationAccountProof,
  encodeInvitationRequest,
  decodeInvitationRequest,
  verifyInvitationDelegation,
  encodeInvitationGrant,
  decodeRoomAdmissionGrant,
  decodeInvitationGrant,
  ROOM_ENDED_MESSAGE,
  encodeInvitationRetirement,
  decodeInvitationRetirement,
  decodeInvitationRetirementNotice,
  retirementError,
  hostRoomInvitation,
  requestRoomAdmissionCapability,
  requestRoomAdmission,
  INVITATION_LABELS,
} from './invitation.js'
export type {
  RoomInvitation,
  RoomInvitationHost,
  InvitationDelegation,
  RoomInvitationDelegate,
  RoomAdmission,
  EncodeInvitationAccountProofOptions,
  EncodeInvitationRequestOptions,
  InvitationRequest,
  DecodeInvitationRequestOptions,
  EncodeInvitationGrantOptions,
  DecodeInvitationGrantOptions,
  HostRoomInvitationOptions,
  EncodeInvitationRetirementOptions,
  RequestRoomAdmissionOptions,
} from './invitation.js'

export {
  encodePersistentInvitation,
  decodePersistentInvitation,
  requestPersistentRoomAdmission,
  PERSISTENT_INVITATION_LABELS,
} from './persistent-invitation.js'
export type { PersistentRoomAdmission } from './persistent-invitation.js'

export { withExpiration, isRoomEnds, requireRoomEnds, MAX_ROOM_ENDS_SECONDS } from './expiration.js'
export { isInvitationRelays, requireInvitationRelays, MAX_INVITATION_RELAYS } from './invitation-relays.js'

export {
  MAX_ROOM_LINK_FRAGMENT_LENGTH,
  parseRoomLink,
  encodeRoomLink,
} from './link.js'
export type { RoomLink } from './link.js'

export {
  EPOCH_ID_INFO,
  EPOCH_KEY_INFO,
  MAX_EPOCH,
  EPOCH_REQUEST_KEY_INFO,
  generateEpochSecret,
  deriveEpoch,
  encodeRekeyEvent,
  peekRekeyEvent,
  readMemberList,
  REPORT_UNKNOWN_EVERY_SECONDS,
  decodeRekeyEvent,
  HISTORY_WINDOW_SECONDS,
  MAX_HISTORY_EPOCHS,
  epochsInWindow,
  deriveEpochRequestKey,
  epochRequestAdmission,
  encodeEpochRequest,
  decodeEpochRequest,
  encodeEpochGrant,
  decodeEpochGrant,
  hostRoomEpoch,
  sealCredential,
  EpochRefusedError,
  requestRoomEpoch,
  canonicalAdmins,
  CHANNEL_NAME,
  RESERVED_CHANNELS,
  canonicalChannels,
  signChannels,
  verifyChannels,
  signAdmins,
  verifyAdmins,
  EPOCH_LABELS,
} from './epoch.js'
export type {
  RoomEpoch,
  EpochKeys,
  EncodeRekeyOptions,
  RekeyRecipient,
  RekeyNotice,
  PeekRekeyOptions,
  DecodeRekeyOptions,
  LeftEpoch,
  EpochRequestAdmissionOptions,
  EncodeEpochRequestOptions,
  DecodeEpochRequestOptions,
  EpochRequest,
  EpochRefusal,
  EncodeEpochGrantOptions,
  DecodeEpochGrantOptions,
  EpochGrant,
  HostRoomEpochOptions,
  RequestRoomEpochOptions,
  SignAdminsOptions,
  SignChannelsOptions,
  VerifyChannelsOptions,
  VerifyAdminsOptions,
} from './epoch.js'

export { EPOCH_COMMIT_PREFIX, epochCommitment, EPOCH_COMMIT_LABELS } from './epoch-commit.js'
export {
  MEMBER_EPOCH_KINDS,
  MEMBER_EPOCH_REQUEST_KEY_INFO,
  MAX_MEMBER_EPOCH_CHAIN,
  deriveMemberEpochRequestKey,
  readRekeyEvidence,
  encodeMemberEpochRequest,
  decodeMemberEpochRequest,
  encodeMemberEpochGrant,
  decodeMemberEpochGrant,
  hostMemberEpochDesk,
  memberEpochSource,
  requestMemberEpoch,
  MEMBER_EPOCH_LABELS,
} from './member-epoch.js'
export type {
  RekeyEvidence,
  EncodeMemberEpochRequestOptions,
  DecodeMemberEpochRequestOptions,
  MemberEpochRequest,
  EncodeMemberEpochGrantOptions,
  DecodeMemberEpochGrantOptions,
  MemberEpochGrant,
  HostMemberEpochDeskOptions,
  MemberEpochRequestOptions,
  MemberEpochSource,
} from './member-epoch.js'

export { deriveChannel, CHANNEL_ID_INFO, CHANNEL_KEY_INFO, MAX_CHANNEL_NAME_LENGTH, CHANNEL_LABELS } from './channel.js'

export {
  LANES,
  LANE_MEANING,
  LANE_LABEL,
  LANE_GLYPH,
  isLane,
  laneOfRelayUrl,
  laneOfRelays,
  weakestLane,
  isDowngrade,
} from './lane.js'
export type { Lane } from './lane.js'

// Opt-in live persistent capability exchange; host lifecycle and epoch gates remain required.
export * from "./live-persistent-admission.js"
