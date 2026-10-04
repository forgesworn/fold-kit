import { schnorr } from '@noble/curves/secp256k1.js'
import { nip44 } from 'nostr-tools'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { hexEquals, normaliseHex } from './hex.js'
import type { DeviceCredential } from './types.js'

/**
 * Seal keys: how a device heals after its key is copied.
 *
 * A device key signs, and until now every rekey copy and every epoch grant
 * was also sealed to it. Whoever copied it opened every one after, until
 * somebody noticed and removed the device. Rotating a receiving key signed
 * by the device key would heal nothing: the thief holds that key and signs
 * their own rotation.
 *
 * So the receiving key rides in the device credential (kind 20460), which
 * the participant signs. A device mints a fresh seal key at every renewal,
 * and its participant's signer, not the device, binds it. Rekeys and grants
 * are sealed to the seal key of the newest credential the sender holds for
 * the device. A thief who copied the device once holds the seal keys of the
 * credentials live at that moment, and none minted after: once the copied
 * credential has lapsed and the room has rekeyed, they are out.
 *
 * A credential with no `seal` tag is sealed to as before, to the device
 * key, so a client that knows nothing of this keeps working, unhealed. See
 * docs/seal-key.md.
 */

/** The credential tag that names a device's seal key. */
export const SEAL_TAG = 'seal'

const HEX64 = /^[0-9a-f]{64}$/i

/** True for an x-only secp256k1 public key: 32-byte hex that lifts to a
 *  point on the curve, so NIP-44 can agree a key with it. */
export function isSealPubkey(value: unknown): value is string {
  if (typeof value !== 'string' || !HEX64.test(value)) return false
  try {
    schnorr.utils.lift_x(BigInt(`0x${value}`))
    return true
  } catch {
    return false
  }
}

export interface SealKey {
  secretKey: Uint8Array
  /** x-only, lower-case hex: what `createDeviceCredential({ seal })` takes. */
  pubkey: string
}

/** A fresh seal key, for the next credential this device asks for. */
export function generateSealKey(): SealKey {
  const secretKey = generateSecretKey()
  return { secretKey, pubkey: getPublicKey(secretKey) }
}

/**
 * The seal key a credential names. Undefined when it names none, and null
 * when its `seal` tags are unusable: more than one, or one that is not a
 * point on the curve. Only the participant could have signed either, so
 * nothing here is an attack, but a sender must not throw on it mid-rekey:
 * it treats null as none.
 */
export function credentialSeal(credential: DeviceCredential): string | undefined | null {
  const tags = credential.tags.filter((t) => t[0] === SEAL_TAG)
  if (tags.length === 0) return undefined
  if (tags.length > 1) return null
  const value = tags[0]![1]
  return isSealPubkey(value) ? normaliseHex(value) : null
}

/**
 * Where to seal something for `device`: the seal key `credential` names, or
 * the device key when it names none, or is not this device's.
 *
 * Expiry is deliberately not checked. A device that has gone quiet for
 * longer than its credential has erased that seal key, so a copy sealed to
 * it is lost, and the device asks for the epoch again when it is back.
 * Falling back to the device key instead would hand that copy to anybody
 * holding a stolen device key, which is the one person healing exists to
 * shut out.
 */
export function sealTarget(device: string, credential?: DeviceCredential): string {
  const to = normaliseHex(device)
  if (!credential) return to
  const named = credential.tags.find((t) => t[0] === 'device')?.[1]
  if (named === undefined || !hexEquals(named, to)) return to
  return credentialSeal(credential) ?? to
}

/** Seal `plaintext` from `senderSk` to `device`, by `sealTarget`. */
export function sealTo(plaintext: string, senderSk: Uint8Array, device: string, credential?: DeviceCredential): string {
  return nip44.v2.encrypt(plaintext, nip44.v2.utils.getConversationKey(senderSk, sealTarget(device, credential)))
}

/**
 * Open something sealed to this device by `sender`: under each seal key in
 * turn, then under the device key. Throws when none of them opens it.
 * NIP-44's MAC verifies under the right key only, so a wrong one fails
 * rather than producing garbage.
 */
export function openSealed(ciphertext: string, sender: string, deviceSk: Uint8Array, sealSks: readonly Uint8Array[] = []): string {
  for (const sk of sealSks) {
    try {
      return nip44.v2.decrypt(ciphertext, nip44.v2.utils.getConversationKey(sk, sender))
    } catch {
      // Not this one: try the next, then the device key.
    }
  }
  return nip44.v2.decrypt(ciphertext, nip44.v2.utils.getConversationKey(deviceSk, sender))
}

function expirationOf(credential: DeviceCredential): number {
  const raw = credential.tags.find((t) => t[0] === 'expiration')?.[1]
  const at = raw === undefined ? NaN : Number(raw)
  return Number.isFinite(at) ? at : -Infinity
}

/**
 * The newer of two credentials: the later expiry, then the later
 * `created_at`. Expiry first because some remote signers restamp
 * `created_at` with their own clock (kithmoot#205), while the expiry is the
 * device's own request, inside the signature either way. Ties keep `a`.
 *
 * Neither is checked here; compare only credentials already verified for
 * the same device.
 */
export function newerCredential(a: DeviceCredential, b: DeviceCredential): DeviceCredential {
  const ea = expirationOf(a)
  const eb = expirationOf(b)
  if (eb !== ea) return eb > ea ? b : a
  return b.created_at > a.created_at ? b : a
}
