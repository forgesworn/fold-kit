import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/hashes/utils'

/**
 * The epoch commitment: what lets a member who is not the authority hand an
 * epoch on, and the requester check it without trusting that member.
 *
 * A rekey event already commits to the secret of the epoch it LEAVES: its
 * body is NIP-44 under that epoch's key, the authority signed the result,
 * and NIP-44's HMAC verifies under no other key. What it does not commit
 * to, in a form a third party can check, is the secret of the epoch it
 * ENTERS - that rides only in the per-device seals, which nobody but the
 * authority and the sealed device can open. This closes that one gap: an
 * optional `commit` field in the (encrypted) rekey body, written by
 * `encodeRekeyEvent` when asked, equal to
 *
 *   HMAC-SHA256(key = secret, "kithmoot/v1/epoch-commit:" + roomId + ":" + epoch)
 *
 * as lower-case hex, `roomId` in lower-case hex and `epoch` in decimal. A
 * PRF keyed by the secret, so the value reveals nothing about it, and bound
 * to the room and the number so a commitment cannot be moved between them.
 * It lives inside the body, not in a tag, so a relay still sees nothing
 * but a number; and it is used nowhere else on the wire, so a removed
 * member who reads the body learns nothing it could find traffic by.
 *
 * Its own module, with no imports from `epoch.ts`, so that `epoch.ts` and
 * `member-epoch.ts` can both use it without an import cycle. See
 * `docs/member-epoch-catch-up.md`.
 */
export const EPOCH_COMMIT_PREFIX = 'kithmoot/v1/epoch-commit:'

const HEX64 = /^[0-9a-f]{64}$/i

/** The commitment a rekey to `epoch` carries for `secret` in `roomId`. */
export function epochCommitment(roomId: string, epoch: number, secret: Uint8Array): string {
  if (!HEX64.test(roomId)) throw new Error('room id must be 32-byte hex')
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error('only an epoch after 0 has a commitment')
  if (secret.length !== 32) throw new Error('epoch secret must be 32 bytes')
  const message = new TextEncoder().encode(`${EPOCH_COMMIT_PREFIX}${roomId.toLowerCase()}:${epoch}`)
  return bytesToHex(hmac(sha256, secret, message))
}

/** Every wire-format literal this module owns, frozen for `src/labels.test.ts`. */
export const EPOCH_COMMIT_LABELS = [
  "kithmoot/v1/epoch-commit:",
] as const
