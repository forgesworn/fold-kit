import type { Event } from 'nostr-tools/pure'

/** Circle-layer wire types: a subset of KithMoot's `src/types.ts`, copied
 * byte-identical per declaration from the pinned source commit (see
 * docs/plans/2026-09-28-circle-kit-extraction.md §1.1 and EXTRACTION.md in
 * this repository). KithMoot's `types.ts` also defines roster, media and
 * descriptor types that stay in KithMoot; those import `Reachability`
 * (KithMoot's `src/reachability.ts`), which does not move here (see the
 * plan's "Corrections after the T0 vector review"). None of the types below
 * need it. */

/** A device credential is an ordinary signed Nostr event, never published bare. */
export type DeviceCredential = Event

/** Kindred tiers, closest first: family, mutual verified bond, one-way
 *  recognition, no requirement at all. */
export type AccessTier = 'open' | 'ken' | 'kith' | 'kin'

/** What a room requires of its agents. `owned-by-members`: an agent is
 *  admitted to the roster only with a verified ownership proof from a
 *  participant who is in the room. See `AgentOwnership`. */
export type AgentRule = 'owned-by-members'

/** A room's admission rule. `admitted` lists the issuer pubkeys the room
 *  trusts to vouch for guests; irrelevant when `tier` is `open`. `agents`
 *  is a separate rule about what an agent has to show; absent means
 *  nothing, which is how every room worked before it existed. */
export interface RoomPolicy {
  tier: AccessTier
  admitted?: string[]
  agents?: AgentRule
  /** When present, the only participants admitted, whatever the tier
   *  says. A direct message is a room whose policy lists two. See
   *  `docs/messages.md`. */
  members?: string[]
  /** A quiet room: its chat rides the kind 1059 firehose as dead drops to
   *  keys derived from the epoch key, on a cadence, so a relay cannot tell
   *  whether anything was said, by whom, or when. Only with `members`,
   *  because everybody derives every member's keys. Rides here so that
   *  everyone who joins agrees on how the room talks, exactly as they
   *  agree on who may enter. See `quiet.ts`. */
  quiet?: true
}

/**
 * A signed claim that `issuer` recognises `participant` at `tier` in `room`,
 * until `expiresAt`. Never issued for `open`, since open needs no proof.
 *
 * `room` is what stops a proof being a bearer token: without it, one proof
 * admits its holder to every room that happens to trust the same issuer, and
 * an issuer who vouched for a guest at one moot has not vouched for them at
 * all of them. The cost of that binding is stated plainly: a kindred proof is
 * a room grant here, not a portable statement about a relationship, so an
 * issuer mints one per room. In this protocol the party who vouches is the
 * party who sent the join link, so it already knows the room id.
 */
export type KindredProof = {
  tier: Exclude<AccessTier, 'open'>
  participant: string
  issuer: string
  /** The room id this proof is valid in. */
  room: string
  /** 32 random bytes, hex, unique to this proof. Signed over, so two proofs
   *  on identical terms are still distinguishable - which is what a revocation
   *  list, or an audit, needs to name one of them. */
  nonce: string
  sig: string
  expiresAt: number
}
