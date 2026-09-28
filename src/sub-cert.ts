import { KINDS } from './kinds.js'
import { verifyEventUncached } from './verify.js'
import { hexEquals, normaliseHex } from './hex.js'
import type { ParticipantIdentity, UnsignedEvent } from './identity.js'
import type { DeviceCredential } from './types.js'

/**
 * Sub-key certificates (kit T3.3).
 *
 * A device credential (`credential.ts`) says a device may act for a
 * participant, in one room or everywhere. An app that signs its own traffic
 * under a further per-scope key - a board's per-epoch signing key, say,
 * derived from the epoch key and never held anywhere but derived on demand
 * (see `scoped.ts`) - needs a second, narrower statement: that THIS
 * credentialled device is the one that minted THIS particular sub-key, for
 * THIS particular scoped id. Without it, a relay (or a receiver) has no way
 * to tell a sub-key's traffic apart from a stranger who also derived a key
 * and started signing with it - the sub-key is not itself proof of anything.
 *
 * The certificate is never published on its own: it rides inside a signed
 * message's ciphertext, alongside the device credential it depends on, so a
 * relay only ever sees the sub-key's signature on outer events and never
 * learns which credentialled device stands behind it.
 *
 * Deliberately its own kind-20460 event with `scope: "sub"`, not a variant
 * `verifyDeviceCredential` accepts: `verifyDeviceCredential` already refuses
 * any `scope` it does not recognise (`credential.ts`, "unknown scope"), so a
 * sub-key certificate can never be mistaken for a room or person credential
 * by the existing verifier, and does not need that function to change at
 * all. Its `device` tag also means something different here - the sub-key
 * being certified, not a device being authorised - so folding it into
 * `verifyDeviceCredential`'s shape would only invite the two to be confused.
 *
 * Exactly four tags, in this fixed order, each exactly `[name, value]`: `d`
 * (the scoped signer id this certificate is for), `device` (the sub-key
 * pubkey), `expiration` (MUST equal the accompanying device credential's
 * `expiration`, compared as the exact tag string - a sub-key certificate
 * never outlives the credential that backs it, and never gets its own
 * independent expiry a caller could set longer by mistake, nor a
 * differently-formatted but numerically-equal one), `scope` (always
 * `"sub"`). `content` MUST be the empty string, matching `credential.ts`'s
 * own convention.
 */
export const SUB_KEY_CERTIFICATE_SCOPE = 'sub'

/** Lower-case or upper-case 32-byte hex - the shape of every pubkey and
 *  scoped id this module handles. Matches `epoch.ts`'s own `HEX64`. */
const HEX64 = /^[0-9a-f]{64}$/i

/** A canonical decimal unix timestamp: no leading/trailing whitespace, no
 *  sign, no `0x` prefix, no fraction, and no leading zeros (other than the
 *  single digit `"0"` itself, which is not a legal expiry here since it
 *  refuses at "expired" but is excluded from ambiguity regardless). Matches
 *  `expiresAt` values `credential.ts` itself would produce with `String()`
 *  on a safe non-negative integer. */
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/

function requireHex64(value: string, what: string): void {
  if (!HEX64.test(value)) throw new Error(`${what} must be 32-byte hex`)
}

export interface CreateSubKeyCertificateOptions {
  /** The credentialled device: the same key a device credential names in
   *  its `device` tag. Signs the certificate. */
  identity: ParticipantIdentity
  /** The scoped id this certificate is for - typically
   *  `deriveScoped(epoch, '<app>/v1/.../signer').id`. Must be 32-byte hex. */
  signerId: string
  /** The sub-key pubkey being certified. Must be 32-byte hex (x-only). */
  subKeyPubkey: string
  /** MUST equal the accompanying device credential's `expiration` exactly.
   *  A safe integer, strictly in the future of `now` (or the real clock). */
  expiresAt: number
  /** Injectable clock, in unix seconds. Defaults to the real one. */
  now?: () => number
}

/**
 * Mint a sub-key certificate. Asynchronous for the same reason
 * `createDeviceCredential` is: the identity may be a remote signer.
 *
 * Validates its own inputs before asking the signer to sign anything: a
 * bad `signerId`/`subKeyPubkey` shape or a non-future `expiresAt` is a
 * caller bug, not something worth turning into a certificate a verifier
 * would refuse for a more confusing reason downstream.
 *
 * Checks what the signer handed back against what was asked for, exactly as
 * `createDeviceCredential` does, so a signer that stamps its own fields (a
 * different `created_at` is fine and deliberately not compared; anything
 * else is not) cannot silently hand back a certificate for something else.
 */
export async function createSubKeyCertificate(opts: CreateSubKeyCertificateOptions): Promise<DeviceCredential> {
  requireHex64(opts.signerId, 'signerId')
  requireHex64(opts.subKeyPubkey, 'subKeyPubkey')
  const now = (opts.now ?? (() => Math.floor(Date.now() / 1000)))()
  if (!Number.isSafeInteger(opts.expiresAt) || opts.expiresAt <= now) {
    throw new Error('expiresAt must be a safe integer unix timestamp in the future')
  }
  const unsigned: UnsignedEvent = {
    kind: KINDS.CREDENTIAL,
    created_at: now,
    tags: [
      ['d', opts.signerId],
      ['device', opts.subKeyPubkey],
      ['expiration', String(opts.expiresAt)],
      ['scope', SUB_KEY_CERTIFICATE_SCOPE],
    ],
    content: '',
  }

  const signed = await opts.identity.signEvent(unsigned)

  if (!hexEquals(signed.pubkey, opts.identity.pubkey)) {
    throw new Error('the signer returned a certificate signed by a different key')
  }
  if (signed.kind !== unsigned.kind || signed.content !== unsigned.content) {
    throw new Error('the signer returned a certificate for something else')
  }
  if (JSON.stringify(signed.tags) !== JSON.stringify(unsigned.tags)) {
    throw new Error('the signer returned a certificate on different terms than it was asked for')
  }
  if (!verifyEventUncached(signed)) {
    throw new Error('the signer returned a certificate that does not verify')
  }

  return signed
}

export type VerifySubKeyCertificateResult =
  | { ok: true; device: string; subKeyPubkey: string }
  | { ok: false; reason: string }

export interface VerifySubKeyCertificateOptions {
  /** The scoped signer id the certificate must name in its `d` tag. */
  signerId: string
  /**
   * The device credential this certificate depends on, ALREADY VERIFIED by
   * the caller (a successful `verifyDeviceCredential` call). This function
   * reads that credential's `device` and `expiration` tags itself, rather
   * than trusting a caller to have copied them out correctly: the
   * certificate's signer (`cert.pubkey`) must equal the credential's
   * `device` tag exactly, and the certificate's `expiration` tag must equal
   * the credential's `expiration` tag as the EXACT SAME STRING (not merely
   * the same number) - so a certificate cannot outlive, or be reissued
   * under a differently-formatted equivalent of, the credential backing it.
   */
  credential: DeviceCredential
  /** The pubkey that signed the message this certificate rode in on - the
   *  sub-key. The certificate's `device` tag must equal it. */
  subKeyPubkey: string
  now: number
  /** The containing message's sign time: the certificate's own `created_at`
   *  must not be later than `at + skewSeconds`. Omit `at` entirely to skip
   *  this bound (a caller with no message context yet, such as a vector,
   *  may not have one). Giving `at` without `skewSeconds` does NOT relax
   *  the bound to unlimited skew - `skewSeconds` then defaults to `0`, a
   *  certificate must not be minted after the message at all. */
  at?: number
  skewSeconds?: number
}

/** Verified sub-key certificates, keyed on the whole signed event exactly as
 *  `credential.ts`'s own bounded cache is: a Schnorr signature is
 *  randomised, so the identical certificate can arrive carrying two
 *  different valid signatures, and an id-keyed cache would refuse the
 *  second. Kept separate from `credential.ts`'s cache because a sub-key
 *  certificate and a device credential are verified under different rules
 *  and neither should be able to poison the other's cache. */
const verifiedSubKeyCertificates = new Set<string>()
function certificateSignature(cert: DeviceCredential): boolean {
  const whole = JSON.stringify([cert.id, cert.pubkey, cert.created_at, cert.kind, cert.tags, cert.content, cert.sig])
  if (verifiedSubKeyCertificates.has(whole)) return true
  if (!verifyEventUncached(cert)) return false
  verifiedSubKeyCertificates.add(whole)
  if (verifiedSubKeyCertificates.size > 4_096) verifiedSubKeyCertificates.delete(verifiedSubKeyCertificates.values().next().value!)
  return true
}

/**
 * Verify a sub-key certificate: that the credentialled device named by
 * `credential` certified `subKeyPubkey` as its sub-key for `signerId`, with
 * an expiry that matches `credential` exactly and a mint time no later than
 * the message it rode in on.
 *
 * Every check below is cheap-first, strict and canonical, and never throws,
 * matching `verifyDeviceCredential`; the signature is checked last, since it
 * is the most expensive and every tag check above invalidates it anyway.
 */
export function verifySubKeyCertificate(cert: DeviceCredential, opts: VerifySubKeyCertificateOptions): VerifySubKeyCertificateResult {
  if (cert.kind !== KINDS.CREDENTIAL) return { ok: false, reason: 'wrong kind' }
  if (cert.content !== '') return { ok: false, reason: 'non-empty content' }

  // Exactly four tags, in this fixed order, each exactly [name, value] (see
  // the module comment): a certificate with an extra, missing or reordered
  // tag, or an extra element tacked onto one tag, is refused before any of
  // its values are even read, so nothing downstream can be tricked by
  // content nobody here is looking for.
  if (cert.tags.length !== 4) return { ok: false, reason: 'wrong tag count' }
  if (cert.tags.some((t) => t.length !== 2)) return { ok: false, reason: 'wrong tag shape' }
  const [dTag, deviceTag, expirationTag, scopeTag] = cert.tags as [string[], string[], string[], string[]]
  if (dTag[0] !== 'd') return { ok: false, reason: 'wrong tag order' }
  if (deviceTag[0] !== 'device') return { ok: false, reason: 'wrong tag order' }
  if (expirationTag[0] !== 'expiration') return { ok: false, reason: 'wrong tag order' }
  if (scopeTag[0] !== 'scope') return { ok: false, reason: 'wrong tag order' }
  if (scopeTag[1] !== SUB_KEY_CERTIFICATE_SCOPE) return { ok: false, reason: 'wrong scope' }

  const signerId = dTag[1]!
  if (!hexEquals(signerId, opts.signerId)) return { ok: false, reason: 'wrong signer' }

  const subKeyPubkey = deviceTag[1]!
  if (!hexEquals(subKeyPubkey, opts.subKeyPubkey)) {
    return { ok: false, reason: 'device tag does not match the message signer' }
  }

  const credentialDevice = opts.credential.tags.find((t) => t[0] === 'device')?.[1]
  if (credentialDevice === undefined) return { ok: false, reason: 'credential missing device tag' }
  if (!hexEquals(cert.pubkey, credentialDevice)) return { ok: false, reason: 'wrong device' }

  const expirationValue = expirationTag[1]!
  if (!CANONICAL_DECIMAL.test(expirationValue)) return { ok: false, reason: 'non-canonical expiration' }
  const credentialExpiration = opts.credential.tags.find((t) => t[0] === 'expiration')?.[1]
  if (credentialExpiration === undefined) return { ok: false, reason: 'credential missing expiration tag' }
  // Exact string comparison, not numeric: "1802582000" and "01802582000" (or
  // any other non-canonical spelling of the same number) must not be
  // treated as equal - CANONICAL_DECIMAL above already refuses the
  // certificate's own tag if it is not canonical, so this compares two
  // already-canonical-or-refused strings, catching a credential whose own
  // tag differs even numerically-identically-formatted.
  if (expirationValue !== credentialExpiration) return { ok: false, reason: 'expiration does not match the credential' }
  const expiresAt = Number(expirationValue)
  if (expiresAt <= opts.now) return { ok: false, reason: 'expired' }

  if (opts.at !== undefined && cert.created_at > opts.at + (opts.skewSeconds ?? 0)) {
    return { ok: false, reason: 'certificate minted after the message it rode in on' }
  }

  if (!certificateSignature(cert)) return { ok: false, reason: 'bad signature' }

  return { ok: true, device: normaliseHex(cert.pubkey), subKeyPubkey: normaliseHex(subKeyPubkey) }
}
