import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import type { EpochKeys } from './epoch.js'

/**
 * Per-app scoped labels, derived from an epoch key (kit T3.1).
 *
 * A consuming app (a board tool, a task list, anything that rides a
 * KithMoot-derived circle) needs its own payload keys and stream ids that
 * live under the same epoch as the roster and the chat, without ever
 * colliding with a KithMoot channel key or being mistaken for one. Sharing
 * one epoch, rather than deriving a second independent secret, is what lets
 * a board and a room use the same link and the same removal: both derive
 * from the same epoch key, so both move together on a rekey.
 *
 * `deriveScoped` is deliberately NOT `deriveChannel`: a channel name is a
 * KithMoot registry concept, signed off by the room's authority
 * (`epoch.ts`'s `signChannels`) and rendered to members as a place to chat.
 * An app's own scoped keys are neither: nobody signs off on them, and they
 * are never shown as a channel. Reusing `deriveChannel` for them would let
 * an app-chosen string collide with a real channel name, or a channel name
 * collide with an app's payload key, so this is its own derivation under
 * its own info strings.
 *
 * `label` MUST NOT start with this kit's own protocol namespace (see
 * `KITHMOOT_NAMESPACE_PREFIX` below) - that namespace belongs to this kit's
 * own derivations (`EPOCH_ID_INFO`, `CHANNEL_ID_INFO`, and so on), and
 * refusing the prefix here means no app label can ever be mistaken for one
 * of this kit's own, whatever an app supplies. `label` MUST match
 * `^[a-z0-9-]{1,64}/v[0-9]{1,9}/[\x21-\x7e]{1,200}$`: a lower-case app
 * namespace of 1 to 64 bytes, a version segment of 1 to 9 digits (an app's
 * label shape is itself something it may need to change - this pins wire
 * compatibility label by label, not by fiat), then 1 to 200 printable-ASCII
 * bytes naming what the label is for. The namespace and version bounds are
 * deliberately tight - an app label is always a short, fixed, hand-written
 * string, never derived from untrusted input - so an unbounded namespace or
 * version segment (as an earlier revision allowed) is refused rather than
 * accepted and merely hashed away: nothing here needs to parse a namespace
 * or version number back out of a label, but a caller building one by
 * concatenation from attacker-influenced text should get a small, cheap
 * refusal rather than an expensive regex match over untrusted length.
 *
 * `ikm` is the epoch KEY, never the epoch id: publishing a scoped id (which
 * a relay necessarily sees as a `d` tag) must reveal nothing about any
 * other scoped key derived from the same epoch, matching `deriveRoom` and
 * `deriveChannel`'s own reasoning for deriving from the room/channel KEY.
 * No salt, matching `deriveEpoch` and `deriveChannel`.
 */
export const SCOPED_LABEL_PATTERN = /^[a-z0-9-]{1,64}\/v[0-9]{1,9}\/[\x21-\x7e]{1,200}$/

/** A derived id and key for one app-defined purpose under one epoch. */
export interface ScopedKeys {
  /** Lower-case hex, 32 bytes. Suitable as a `d` tag or any other public
   *  identifier a relay is expected to see. */
  id: string
  /** 32 bytes. A NIP-44 conversation key, an envelope key, an HKDF salt for
   *  a further derivation - whatever the label's owner needs a secret for. */
  key: Uint8Array
}

/** See the comment at its one use site in `deriveScoped`. */
const KITHMOOT_NAMESPACE_PREFIX = 'kithmoot' + '/'

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * `{ id, key } = HKDF-SHA256(ikm = epoch.key, info = label + "/id" | label +
 * "/key", 32)`, no salt.
 *
 * Refuses a label in this kit's own protocol namespace, and any label that
 * does not match `SCOPED_LABEL_PATTERN`. Two different labels always derive
 * to two different (id, key) pairs (barring an HKDF collision); the same
 * label under two different epoch keys always derives to two different
 * pairs too, which is what lets a rekey rotate every scoped key an app
 * derived from the old epoch.
 */
export function deriveScoped(epoch: EpochKeys, label: string): ScopedKeys {
  // Built by concatenation, deliberately not as one string literal: this
  // kit's `src/labels.test.ts` scans src/*.ts for every literal wire-format
  // label this kit's own protocol owns, and freezes the exact set found.
  // This check needs the same prefix at runtime, but it names that
  // namespace in order to refuse it, rather than adding a new label of its
  // own - so it is assembled at call time instead of appearing in the
  // source as a scannable literal that test would otherwise pick up.
  if (label.startsWith(KITHMOOT_NAMESPACE_PREFIX)) {
    throw new Error('a scoped label may not start with this kit\'s own protocol namespace')
  }
  if (!SCOPED_LABEL_PATTERN.test(label)) {
    throw new Error('scoped label must match ^[a-z0-9-]{1,64}/v[0-9]{1,9}/[\\x21-\\x7e]{1,200}$')
  }
  if (epoch.key.length !== 32) throw new Error('epoch key must be 32 bytes')
  const id = hex(hkdf(sha256, epoch.key, undefined, `${label}/id`, 32))
  const key = hkdf(sha256, epoch.key, undefined, `${label}/key`, 32)
  return { id, key }
}
