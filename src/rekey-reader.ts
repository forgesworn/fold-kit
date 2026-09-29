import { nip44 } from 'nostr-tools'
import type { Event } from 'nostr-tools/pure'
import { base64urlnopad } from '@scure/base'
import { peekRekeyEvent, type EpochKeys, type PeekRekeyOptions, type RekeyNotice } from './epoch.js'
import { normaliseHex } from './hex.js'

/** An optional external-signer capability; ParticipantIdentity remains signing-only. */
export interface Nip44Decryptor {
  readonly pubkey: string
  readonly nip44: { decrypt(peerPubkey: string, ciphertext: string): Promise<string> }
}

export interface DecodeRekeyEnvelopeOptions extends PeekRekeyOptions { current: EpochKeys }
export interface DecodeRekeyWithSignerOptions extends DecodeRekeyEnvelopeOptions { signer: Nip44Decryptor }
export interface RekeyEnvelope {
  notice: Omit<RekeyNotice, 'secret' | 'catchUp'>
  sealedKeys: Readonly<Record<string, string>>
}

/** Upper bound before signature hashing; accommodates the v2 cipher's maximum body. */
export const MAX_REKEY_CONTENT_LENGTH = 90_000
const HEX = /^[0-9a-f]{64}$/i
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

/**
 * Validate a complete v1 rekey body without opening a recipient copy. Fork selection
 * must use this result, independently of whether a particular recipient has a copy.
 * Existing synchronous decodeRekeyEvent and its legacy wire behaviour stay unchanged.
 */
export function decodeRekeyEnvelope(event: Event, opts: DecodeRekeyEnvelopeOptions): RekeyEnvelope | null {
  try {
    if (typeof event.content !== 'string' || event.content.length > MAX_REKEY_CONTENT_LENGTH) return null
    if (!Number.isSafeInteger(event.created_at) || event.created_at < 0) return null
    if (!Array.isArray(event.tags) || event.tags.length !== 2 ||
        event.tags[0]?.length !== 2 || event.tags[0]?.[0] !== 'd' ||
        event.tags[1]?.length !== 2 || event.tags[1]?.[0] !== 'epoch') return null
    const epoch = peekRekeyEvent(event, opts)
    if (epoch === null || epoch !== opts.current.epoch + 1) return null
    const body: unknown = JSON.parse(nip44.v2.decrypt(event.content, opts.current.key))
    if (!object(body) || body.v !== 1 || body.epoch !== epoch ||
        Object.keys(body).some((key) => !['v', 'epoch', 'removed', 'by', 'closed', 'keys'].includes(key))) return null
    if (!Array.isArray(body.removed) || !body.removed.every((p) => typeof p === 'string' && HEX.test(p))) return null
    if (body.by !== undefined && (typeof body.by !== 'string' || !HEX.test(body.by))) return null
    if (body.closed !== undefined && body.closed !== true) return null
    if (!object(body.keys)) return null
    const sealedKeys: Record<string, string> = Object.create(null)
    for (const [to, sealed] of Object.entries(body.keys)) {
      if (!HEX.test(to) || typeof sealed !== 'string' || !sealed.length) return null
      const recipient = normaliseHex(to)
      if (Object.hasOwn(sealedKeys, recipient)) return null
      sealedKeys[recipient] = sealed
    }
    if (body.closed === true && Object.keys(sealedKeys).length !== 0) return null
    return {
      notice: { epoch, at: event.created_at, removed: [...new Set(body.removed.map(normaliseHex))].sort(),
        closed: body.closed === true, ...(typeof body.by === 'string' ? { by: normaliseHex(body.by) } : {}) },
      sealedKeys,
    }
  } catch { return null }
}

/** Cancellation/disconnection is operational: it must not discard a valid fork winner. */
export class RekeySignerError extends Error {
  constructor(cause: unknown) { super('The signer could not open its rekey copy', { cause }); this.name = 'RekeySignerError' }
}

/**
 * Open only this signer's copy of an authenticated rekey. Malformed event/plaintext:
 * null. No copy: valid notice with no secret. Signer failure: RekeySignerError.
 * The caller handles missing copies; this reader never invokes an epoch desk.
 */
export async function decodeRekeyEventWithSigner(event: Event, opts: DecodeRekeyWithSignerOptions): Promise<RekeyNotice | null> {
  const envelope = decodeRekeyEnvelope(event, opts)
  if (!envelope) return null
  const pubkey = opts.signer.pubkey
  if (typeof pubkey !== 'string' || !HEX.test(pubkey)) throw new TypeError('Signer pubkey must be 32-byte hex')
  const mine = envelope.sealedKeys[normaliseHex(pubkey)]
  if (mine === undefined) return envelope.notice
  let plaintext: string
  try { plaintext = await opts.signer.nip44.decrypt(event.pubkey, mine) }
  catch (error) { throw new RekeySignerError(error) }
  try {
    if (typeof plaintext !== 'string' || plaintext.length > 256) return null
    const value: unknown = JSON.parse(plaintext)
    if (!object(value) || Object.keys(value).length !== 2 || value.v !== 1 || typeof value.secret !== 'string') return null
    const secret = base64urlnopad.decode(value.secret)
    if (secret.length !== 32 || base64urlnopad.encode(secret) !== value.secret) return null
    return { ...envelope.notice, secret }
  } catch { return null }
}
