import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'

/** `deriveChannel`, extracted from KithMoot's `src/chat.ts` (see
 * EXTRACTION.md).
 * `ChatLog` and the chat event codecs stay in KithMoot. */

export const CHANNEL_ID_INFO = 'kithmoot/v1/channel-id/'
export const CHANNEL_KEY_INFO = 'kithmoot/v1/channel-key/'
/** Bounds a channel name, which rides only in an HKDF info string and
 *  never on the wire; long enough for any sensible name. */
export const MAX_CHANNEL_NAME_LENGTH = 64

/**
 * The room id and key a named channel lives under.
 *
 * Both derived from the room KEY, never the room id, so a party that holds
 * the id and not the key - a forwarder, a relay - cannot find the channel
 * from the room, let alone read it. Two separate HKDF expansions for the
 * same reason `deriveRoom` uses two: publishing the id reveals nothing about
 * the key. The main chat is the unnamed channel and is untouched by this:
 * its id is the room id and its key the room key, byte for byte as before.
 */
export function deriveChannel(roomId: string, roomKey: Uint8Array, channel?: string): { id: string; key: Uint8Array } {
  if (channel === undefined) return { id: roomId, key: roomKey }
  if (channel.length === 0 || channel.length > MAX_CHANNEL_NAME_LENGTH) throw new Error('channel name out of range')
  const idBytes = hkdf(sha256, roomKey, undefined, CHANNEL_ID_INFO + channel, 32)
  const key = hkdf(sha256, roomKey, undefined, CHANNEL_KEY_INFO + channel, 32)
  const id = Array.from(idBytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return { id, key }
}

/** Every wire-format literal this module owns (each one a kithmoot protocol string), frozen for
 *  `src/labels.test.ts`, which checks each module against its own exported
 *  list rather than scanning file text for matching comments. Pure data -
 *  adding this export changes no runtime behaviour. */
export const CHANNEL_LABELS = [
  "kithmoot/v1/channel-id/",
  "kithmoot/v1/channel-key/",
] as const
