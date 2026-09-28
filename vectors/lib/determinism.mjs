// Shared low-level helpers for deriving byte-identical crypto output from
// fixed, labelled inputs. Used by both `generate.mjs` (which builds the
// vectors) and `verify.test.ts` (which recomputes them independently to
// prove the JSON file was not hand-edited into something the derivation no
// longer produces).
//
// Nothing in here is a KithMoot primitive in its own right - it is the
// smallest amount of code needed to call the *real* cryptographic building
// blocks (`@noble/curves` schnorr, NIP-44) with explicit, recorded
// randomness in place of the random defaults `src/` uses in production.

import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils'
import { schnorr } from '@noble/curves/secp256k1.js'
import { getEventHash } from 'nostr-tools/pure'

const NAMESPACE = 'kithmoot/v1/vectors'

/**
 * A fixed 32-byte value derived from a label: an aux-rand seed, a NIP-44
 * nonce, or an edge-case room secret. Deterministic and stable across runs,
 * which is the entire point of a test vector - two people (or two
 * languages) hashing the same label always get the same bytes.
 */
export function seed32(label) {
  return sha256(utf8ToBytes(`${NAMESPACE}/${label}`))
}

/**
 * A valid secp256k1 secret key derived from a label.
 *
 * `schnorr.utils.randomSecretKey` maps an arbitrary 48-byte seed onto a
 * uniformly valid scalar in [1, n-1] via `mapHashToField`, so any 48-byte
 * input - not only a real CSPRNG draw - produces a usable key. Feeding it a
 * fixed, labelled HKDF output instead of random bytes is the documented way
 * to get a reproducible key out of that API, and it is what lets an
 * independent implementation regenerate exactly PARTICIPANT_A's key pair
 * from the label alone.
 */
export function deriveSecretKey(label) {
  const ikm = sha256(utf8ToBytes(`${NAMESPACE}/sk-ikm/${label}`))
  const seed48 = hkdf(sha256, ikm, undefined, `${NAMESPACE}/sk/${label}`, 48)
  return schnorr.utils.randomSecretKey(seed48)
}

/**
 * Build a signed Nostr event exactly as nostr-tools' `finalizeEvent` does
 * (see `node_modules/nostr-tools/lib/esm/pure.js`), except with an explicit
 * BIP-340 aux-rand in place of a random one.
 *
 * Every event-signing call in `src/` goes through `finalizeEvent`, which
 * signs with `schnorr.sign(hash, secretKey)` - no third argument, so
 * `@noble/curves` draws 32 fresh random bytes for aux-rand on every call.
 * That is correct for production (BIP-340 recommends randomising aux-rand
 * as side-channel hardening) and means two calls with identical inputs
 * never produce the same signature. A vector needs the opposite: the exact
 * same bytes on every run, on every machine. Fixing aux-rand to a recorded
 * seed is what the official BIP-340 test vectors do for exactly this
 * reason - it does not weaken the signature, because aux-rand only needs to
 * be unpredictable in a live signer, never in a frozen fixture.
 */
export function finalizeDeterministic(template, secretKey, auxRand) {
  const pubkey = bytesToHex(schnorr.getPublicKey(secretKey))
  const unsigned = { ...template, pubkey }
  const id = getEventHash(unsigned)
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), secretKey, auxRand))
  return { ...unsigned, id, sig }
}

/**
 * Run `fn` with `globalThis.crypto.getRandomValues` replaced by a stub that
 * serves 32-byte values off `queue`, in order, then restores the original.
 *
 * This is how a REAL encoder - one that calls `finalizeEvent` or
 * `nip44.v2.encrypt` with no explicit nonce/aux-rand, and so draws it at
 * random - is driven deterministically without changing a byte of its
 * production code path: `@noble/hashes`' `randomBytes` (which every random
 * draw in `src/` bottoms out at, whether through `@noble/curves` schnorr
 * signing or nostr-tools' NIP-44) reads `globalThis.crypto.getRandomValues`
 * on every call (`node_modules/@noble/hashes/esm/utils.js`), so replacing
 * that one function intercepts every draw the real function makes, in the
 * order it makes them. Confirmed to reach `randomBytes`, `schnorr.sign` and
 * `nip44.v2.encrypt` under vitest, not only under plain Node.
 *
 * `fn` may be sync or async; either way every draw it makes while running is
 * served from `queue`, in order, and the stub is removed again once `fn`
 * settles - a queue entry is never reused between calls, and a caller that
 * draws more than `queue.length` times fails loudly rather than silently
 * reading real randomness.
 *
 * On a SUCCESSFUL call (`fn` returns or resolves without throwing) the whole
 * queue must be drawn - a recorded value that the real function never
 * actually asked for is a vector that pins the wrong thing (a stray or
 * miscounted entry that happens not to matter, rather than every byte a
 * real call draws), so this throws rather than silently ignoring it. Not
 * enforced on a throw: a call that fails partway through is expected to
 * have drawn fewer than the recorded queue, and the caller's own error is
 * the one worth seeing.
 */
export function withStubbedRandomness(queue, fn) {
  const values = [...queue]
  let i = 0
  const target = globalThis.crypto
  const original = target.getRandomValues.bind(target)
  target.getRandomValues = (arr) => {
    const next = values[i]
    if (!next) throw new Error(`withStubbedRandomness: queue exhausted after ${i} draw(s)`)
    if (next.length !== arr.length) {
      throw new Error(`withStubbedRandomness: draw ${i} wants ${arr.length} bytes, queue entry has ${next.length}`)
    }
    arr.set(next)
    i += 1
    return arr
  }
  const restore = () => { target.getRandomValues = original }
  const checkFullyConsumed = () => {
    if (i !== values.length) {
      throw new Error(`withStubbedRandomness: queue had ${values.length} entr${values.length === 1 ? 'y' : 'ies'} but the real call only drew ${i}`)
    }
  }
  let result
  try {
    result = fn()
  } catch (err) {
    restore()
    throw err
  }
  if (result instanceof Promise) {
    return result.then(
      (value) => { restore(); checkFullyConsumed(); return value },
      (err) => { restore(); throw err },
    )
  }
  restore()
  checkFullyConsumed()
  return result
}

/**
 * The exact bytes a kindred proof signs over.
 *
 * Mirrors `canonicalMessage` in `src/access.ts` byte for byte - that
 * function is not exported, because callers have no business constructing
 * this message themselves, so it is reproduced here deliberately rather
 * than imported. If the two ever disagree, `verify.test.ts`'s
 * access-evaluation assertions against the real `evaluateAccess` will fail.
 */
export function kindredCanonicalMessage(tier, participant, room, nonce, expiresAt) {
  return sha256(utf8ToBytes(`kithmoot/v1/kindred:${tier}:${participant}:${room}:${nonce}:${expiresAt}`))
}
