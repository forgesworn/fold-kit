import { KINDS } from './kinds.js'
import { verifyEventUncached } from './verify.js'
import { hexEquals, normaliseHex } from './hex.js'
import type { ParticipantIdentity, UnsignedEvent } from './identity.js'
import type { DeviceCredential } from './types.js'

export interface CreateCredentialOptions {
  /**
   * The participant. A locally held key (`localIdentity`) or an external
   * signer - see `ParticipantIdentity`. Either way the secret itself never
   * reaches this function.
   */
  identity: ParticipantIdentity
  /** The pubkey of the device being authorised. */
  devicePubkey: string
  /**
   * The room this credential is for. Omit it, and pass `scope: 'person'`,
   * for a credential that lets the device act for the participant in every
   * room, DM and box: the same event with `d` set to the participant's own
   * pubkey and a `scope` tag, so a verifier that knows one form knows the
   * other. See docs/device-credential.md.
   */
  roomId?: string
  /** `person` widens the credential from one room to the participant. */
  scope?: 'person'
  /** What the person calls this device. Shown to them and to nobody else. */
  label?: string
  /** Unix seconds. A person credential may not run more than 30 days. */
  expiresAt: number
  /** Injectable clock, in unix seconds. Defaults to the real one. */
  now?: () => number
}

/** The longest a person-scoped credential may run. A phone that leaves the house is better at seven days. */
export const PERSON_CREDENTIAL_MAX_SECONDS = 30 * 24 * 60 * 60

/**
 * Authorise a device to act for a participant in one room, until an expiry.
 *
 * The credential is signed by the participant key but is never published to a
 * relay - it travels inside the room-key-encrypted roster, so relays never
 * learn the participant pubkey.
 *
 * Asynchronous because the signer may not be here: an extension has to
 * prompt, a bunker has to be reached over a relay, a phone has to be
 * unlocked. See `ParticipantIdentity`.
 */
export async function createDeviceCredential(opts: CreateCredentialOptions): Promise<DeviceCredential> {
  const now = (opts.now ?? (() => Math.floor(Date.now() / 1000)))()
  const person = opts.scope === 'person'
  if (person && opts.roomId !== undefined) throw new Error('a person credential names no room')
  if (!person && opts.roomId === undefined) throw new Error('a room credential needs a room')
  if (person && opts.expiresAt - now > PERSON_CREDENTIAL_MAX_SECONDS) throw new Error('a person credential may not run more than 30 days')
  const unsigned: UnsignedEvent = {
    kind: KINDS.CREDENTIAL,
    created_at: now,
    tags: [
      ['d', person ? opts.identity.pubkey : opts.roomId!],
      ['device', opts.devicePubkey],
      ['expiration', String(opts.expiresAt)],
      ...(person ? [['scope', 'person']] : []),
      ...(opts.label !== undefined ? [['label', opts.label]] : []),
    ],
    content: '',
  }

  const signed = await opts.identity.signEvent(unsigned)

  // A signer is not part of this codebase: it is a browser extension, a
  // bunker on somebody else's machine, or an app on a phone. It is trusted
  // to hold the key, not to be correct - and a credential is the one thing
  // in this protocol that says who a device speaks for. So what comes back
  // is checked against what was asked for, rather than returned on faith.
  //
  // `created_at` is deliberately NOT compared: some signers stamp their own,
  // it is inside the signature either way, and nothing here decides anything
  // on it - the `expiration` tag is what bounds the credential, and that IS
  // compared.
  if (!hexEquals(signed.pubkey, opts.identity.pubkey)) {
    throw new Error('the signer returned a credential signed by a different key')
  }
  if (signed.kind !== unsigned.kind || signed.content !== unsigned.content) {
    throw new Error('the signer returned a credential for something else')
  }
  if (JSON.stringify(signed.tags) !== JSON.stringify(unsigned.tags)) {
    throw new Error('the signer returned a credential on different terms than it was asked for')
  }
  if (!verifyEventUncached(signed)) {
    throw new Error('the signer returned a credential that does not verify')
  }

  return signed
}

export type VerifyResult =
  | { ok: true; participant: string; device: string }
  | { ok: false; reason: string }

/**
 * Verify a credential for one room (`roomId`) or for the person (`identity`,
 * the participant pubkey the verifier expects). A person credential is
 * accepted where a room credential is expected only when the caller says
 * so with `acceptPerson`, which a room does when it admits the person and
 * so admits their devices. A room credential is never accepted as a person
 * credential, and a room credential carrying a `scope` tag is refused.
 */
/** A credential rides on every message and presence its device sends, so
 *  the same one reaches this check again and again: checking its signature
 *  afresh each time was half of what opening an old room cost. Keyed on the
 *  whole event, signature included: a Schnorr signature is randomised, so
 *  one credential can carry two valid signatures, and an id-keyed cache
 *  would refuse the second. */
const verifiedCredentials = new Set<string>()
function credentialSignature(cred: DeviceCredential): boolean {
  const whole = JSON.stringify([cred.id, cred.pubkey, cred.created_at, cred.kind, cred.tags, cred.content, cred.sig])
  if (verifiedCredentials.has(whole)) return true
  if (!verifyEventUncached(cred)) return false
  verifiedCredentials.add(whole)
  if (verifiedCredentials.size > 4_096) verifiedCredentials.delete(verifiedCredentials.values().next().value!)
  return true
}

export function verifyDeviceCredential(
  cred: DeviceCredential,
  opts: { roomId: string; now: number; acceptPerson?: boolean } | { identity: string; now: number },
): VerifyResult {
  if (cred.kind !== KINDS.CREDENTIAL) return { ok: false, reason: 'wrong kind' }

  const d = cred.tags.find((t) => t[0] === 'd')?.[1]
  const scope = cred.tags.find((t) => t[0] === 'scope')?.[1]
  if (d === undefined) return { ok: false, reason: 'no scope' }
  const isPerson = scope === 'person'
  if (scope !== undefined && !isPerson) return { ok: false, reason: 'unknown scope' }
  if ('identity' in opts) {
    if (!isPerson) return { ok: false, reason: 'not a person credential' }
    if (!hexEquals(d, opts.identity) || !hexEquals(d, cred.pubkey)) return { ok: false, reason: 'wrong person' }
  } else if (isPerson) {
    if (!opts.acceptPerson) return { ok: false, reason: 'person credential where a room credential was expected' }
    if (!hexEquals(d, cred.pubkey)) return { ok: false, reason: 'wrong person' }
  } else if (!hexEquals(d, opts.roomId)) {
    return { ok: false, reason: 'wrong room' }
  }

  const expiration = cred.tags.find((t) => t[0] === 'expiration')?.[1]
  // A missing tag and a present-but-non-numeric one are the same failure:
  // there is no usable expiry to check against. Folding them into one
  // `Number.isFinite` guard matters because `Number(expiration)` on
  // anything non-numeric is NaN, and every comparison with NaN - including
  // `NaN <= now` - is false, so the naive check below would treat a
  // corrupted tag as never expiring: a fail-open default in a security
  // check, even though the tag sits inside the signed content today and so
  // is not exploitable while the signature check below still runs.
  const expiresAt = expiration === undefined ? NaN : Number(expiration)
  if (!Number.isFinite(expiresAt)) return { ok: false, reason: 'no expiration' }
  if (expiresAt <= opts.now) return { ok: false, reason: 'expired' }
  if (isPerson && expiresAt - cred.created_at > PERSON_CREDENTIAL_MAX_SECONDS) return { ok: false, reason: 'longer than 30 days' }

  const device = cred.tags.find((t) => t[0] === 'device')?.[1]
  if (!device) return { ok: false, reason: 'no device' }

  // Signature last: it is the most expensive check, and tampering with any tag
  // above invalidates it anyway. Never nostr-tools' own cached verdict, which
  // a credential could arrive carrying - see `verify.ts` - but our bounded
  // cache, which matches only the identical event.
  if (!credentialSignature(cred)) return { ok: false, reason: 'bad signature' }

  // A credential is one of the places a device/participant pubkey enters
  // the system - the `device` tag in particular is free text set by
  // whoever minted the credential. Canonicalise both here so every caller
  // (roster decode, secondary-device adoption) compares against something
  // already lower-case, rather than each having to know to.
  return { ok: true, participant: normaliseHex(cred.pubkey), device: normaliseHex(device) }
}
