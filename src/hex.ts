/**
 * Case-insensitive equality for hex identifiers.
 *
 * Nostr pubkeys, room ids, and every other hex field this protocol compares
 * are canonically produced in lower case, but nothing on the wire enforces
 * that: an allow-list entry typed or pasted by a person, in particular, may
 * carry upper-case hex naming exactly the same key. Every place this
 * protocol decides whether two hex identifiers name the same thing must go
 * through this function rather than `===`/`!==`, so a case difference is
 * never mistaken for a different identity - see `vectors/README.md`.
 */
export function hexEquals(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase()
}

/**
 * Canonicalise a hex identifier to lower case.
 *
 * `hexEquals` makes an equality check safe regardless of case, but nothing
 * protects a *lexicographic* comparison the same way: `Peer`'s glare
 * tiebreak and `resolveSingularRoles`' device tiebreak both order hex
 * strings with `<`, and two implementations that disagree on which of two
 * differently-cased spellings of the same identifier sorts first can reach
 * opposite answers from identical input - the exact deadlock perfect
 * negotiation exists to prevent. Call this once, at the point a hex
 * identifier enters the system - a decoded event, a parsed credential or
 * proof, a pubkey read from storage or a URL - rather than at each
 * comparison site, so every later equality or ordering check on it is
 * correct by construction. See `vectors/README.md`.
 */
export function normaliseHex(hex: string): string {
  return hex.toLowerCase()
}
