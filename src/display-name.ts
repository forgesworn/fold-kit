/**
 * Display names.
 *
 * A name in this protocol is **self-asserted**: whoever holds a participant
 * key types whatever they like, and nothing anywhere checks it. That is the
 * point - joining a room should cost a name and nothing else - but it means
 * a name is attacker-controlled text arriving off a relay, and every reader
 * has to treat it as such.
 *
 * Two rules follow, and they live in different places:
 *
 *   1. **Sanitise it.** Everything below. A name may not carry characters
 *      that let it take a second row, hide part of itself, or reverse the
 *      direction the rest of the line renders in, and it may not be long
 *      enough to push everything else off the row.
 *
 *   2. **Never render it alone, and never as HTML.** Both are the caller's
 *      job, because both are about what a name sits next to. A short pubkey
 *      always renders beside it, so two people called "Robin" stay
 *      distinguishable and an impersonation is visible; and it goes in via
 *      `textContent`, never `innerHTML`, so markup in a name stays text.
 */

/**
 * How long a name may be, in characters.
 *
 * Counted in code points rather than UTF-16 units, so one emoji costs one -
 * a cap in UTF-16 units would let an astral-plane name be twice as wide as
 * an ASCII one, and could cut a surrogate pair in half.
 */
export const MAX_DISPLAY_NAME_LENGTH = 32

/**
 * Every Unicode "other" character: controls (Cc), format characters (Cf),
 * surrogates (Cs), private use (Co) and unassigned code points (Cn).
 *
 * That single class covers the whole family of tricks a name is used for:
 * a newline taking a second row, a bidirectional override (U+202E and
 * friends) making the rest of the line render backwards, a zero-width
 * space hiding the difference between two names, a byte-order mark padding
 * one invisibly. Naming the class rather than listing the code points is
 * deliberate: the list grows with Unicode, and a filter that has to be
 * updated to stay correct is a filter that will one day be out of date.
 *
 * It also removes U+200D ZERO WIDTH JOINER, so a joined emoji sequence
 * comes apart into its parts. That is a real cost, accepted knowingly: an
 * invisible character that changes what a name looks like is exactly the
 * thing being removed, and there is no way to keep one and not the other.
 */
const INVISIBLE = /\p{C}/gu

/** Any run of whitespace, including the Unicode ones. */
const WHITESPACE = /\s+/gu

/**
 * Make a name safe to put next to somebody else's, or return undefined if
 * there is nothing left worth showing.
 *
 * Takes `unknown` because this runs on JSON off a relay as well as on a
 * field somebody typed, and anything at all can arrive in either.
 */
export function sanitiseDisplayName(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined

  // Whitespace first, invisibles second, and the order matters: a newline
  // is itself a control character, so stripping controls first would turn
  // "Robin\nadmin" into one word rather than two - hiding the smuggled
  // line break instead of defusing it.
  const collapsed = raw.replace(WHITESPACE, ' ').replace(INVISIBLE, '').replace(WHITESPACE, ' ').trim()
  if (!collapsed) return undefined

  // Split into code points before slicing: `String.prototype.slice` counts
  // UTF-16 units and would cut a surrogate pair in half, leaving a lone
  // surrogate on the wire.
  const characters = [...collapsed]
  if (characters.length <= MAX_DISPLAY_NAME_LENGTH) return collapsed
  // Re-trimmed, because the cap can land mid-word and leave a trailing
  // space that would then render as a name ending in nothing.
  const capped = characters.slice(0, MAX_DISPLAY_NAME_LENGTH).join('').trim()
  return capped || undefined
}
