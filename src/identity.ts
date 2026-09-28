import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure'
import { normaliseHex } from './hex.js'

/**
 * An event with everything filled in except the three fields a signature
 * produces: `pubkey`, `id`, `sig`.
 *
 * Deliberately the same shape an external signer expects - NIP-07's
 * `window.nostr.signEvent`, NIP-46's `sign_event`, and signet-login's
 * `SignetSigner.signEvent` all take exactly this - so a signer built for
 * any of those satisfies the interface below without an adapter.
 */
export interface UnsignedEvent {
  kind: number
  created_at: number
  tags: string[][]
  content: string
}

/**
 * The person, as far as this protocol is concerned.
 *
 * The participant key is used for exactly one thing: signing a device
 * credential, one small event per room. Everything else in a room already
 * runs on other keys - the device key signs the roster and the gift-wrapped
 * signalling, the room key encrypts the roster and the chat. So this is the
 * whole surface an identity has to cover.
 *
 * That narrowness is what makes an external signer practical, and the
 * reason to prefer one: a participant who signs in with a browser extension
 * or a remote bunker never has a participant secret in this app's storage
 * at all. `localIdentity` is the other implementation - a key generated and
 * held here, which is the zero-friction default and is exactly as valid.
 *
 * `signEvent` is async because a remote signer is a round trip: an
 * extension prompt, a relay hop to a bunker, a tap on a phone. Every caller
 * in this library awaits it rather than assuming an answer is available in
 * the same tick.
 */
export interface ParticipantIdentity {
  /** Lower-case hex. See `normaliseHex`. */
  readonly pubkey: string
  signEvent(unsigned: UnsignedEvent): Promise<Event>
}

/**
 * An identity backed by a secret key held in this process.
 *
 * The key never leaves the closure, which is the same guarantee the app
 * gave before this seam existed - it is simply now one implementation of an
 * interface rather than the only way to be a participant.
 */
export function localIdentity(participantSk: Uint8Array): ParticipantIdentity {
  return {
    pubkey: normaliseHex(getPublicKey(participantSk)),
    async signEvent(unsigned: UnsignedEvent): Promise<Event> {
      return finalizeEvent(unsigned, participantSk)
    },
  }
}
