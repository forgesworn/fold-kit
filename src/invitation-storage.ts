/**
 * A room's own storage nodes, carried in its signed group invitation (kind 1463).
 *
 * A room that keeps its files on its own computers lists their base URLs
 * here, so a client uploads to those and never to a public server. The list is
 * signed by the room's authority and rides in the encrypted body, after
 * `relays`; a body without it says nothing about storage.
 *
 * An entry is one string, a node's canonical base URL, and nothing else: the
 * `server` a token names is its host, and scopes, ceilings and expiry belong
 * to the grant. Canonical is defined by this grammar, not by what a URL parser
 * prints, so a port written in another language gets the same answers:
 *
 *     entry   = scheme "://" host [ ":" port ] *( "/" segment )
 *     scheme  = "https" / "http"
 *     host    = label *( "." label )            ; 1 to 253 characters
 *     label   = 1*63( a-z / 0-9 / "-" )         ; not starting or ending with "-"
 *     port    = "1"-"9" *4DIGIT                 ; 1 to 65535, no leading zero
 *     segment = 1*( A-Z / a-z / 0-9 / "." / "_" / "~" / "-" ) ; not "." or ".."
 *
 * and: at most 256 characters; `http` only for `localhost`, a loopback
 * address `127.a.b.c` or an onion v3 host; no default port; a host whose last
 * label is all digits or `0x` hex must be exactly four decimal octets with no
 * leading zero; no trailing slash; no user info, query or fragment.
 *
 * The list is strict: 0 to `MAX_INVITATION_STORAGE_NODES` entries, no two on
 * one host (grants are per host), order preserved and significant. `[]` means
 * the authority withdrew every node. Anything else refuses the whole envelope.
 */

/** At most this many group storage nodes in a room's invitation. */
export const MAX_INVITATION_STORAGE_NODES = 8
/** The longest canonical node base URL. */
export const MAX_STORAGE_NODE_URL_LENGTH = 256

/** A canonical node base URL and the `server` tag it implies (its host). */
export interface StorageNode {
  base: string
  server: string
}

const MAX_HOST_LENGTH = 253
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const PORT = /^[1-9][0-9]{0,4}$/
const SEGMENT = /^[A-Za-z0-9._~-]+$/
const OCTET = /^(?:0|[1-9][0-9]{0,2})$/
const HEX_LABEL = /^0x[0-9a-f]*$/
const DIGITS = /^[0-9]+$/
const LOOPBACK = /^127\.[0-9]+\.[0-9]+\.[0-9]+$/
const ONION_V3 = /^[a-z2-7]{56}\.onion$/
/** Entry as written: scheme, host characters, optional port, path segments. */
const ENTRY = /^(https?):\/\/([a-z0-9.-]+)(?::([0-9]*))?((?:\/[^/]*)*)$/

/** A host the grammar allows, with the "ends in a number" rule applied. */
function isCanonicalHost(host: string): boolean {
  if (host.length < 1 || host.length > MAX_HOST_LENGTH) return false
  const labels = host.split('.')
  if (!labels.every(label => LABEL.test(label))) return false
  const last = labels[labels.length - 1]!
  if (DIGITS.test(last) || HEX_LABEL.test(last)) {
    if (labels.length !== 4) return false
    return labels.every(label => OCTET.test(label) && Number(label) <= 255)
  }
  return true
}

/** True for a host that may be reached over plain http. */
function isPlainHttpHost(host: string): boolean {
  return host === 'localhost' || LOOPBACK.test(host) || ONION_V3.test(host)
}

function isCanonicalPort(port: string): boolean {
  return PORT.test(port) && Number(port) <= 65_535
}

function isCanonicalPath(path: string): boolean {
  if (path === '') return true
  // Every segment is non-empty (so no trailing slash, no "//"), and neither "." nor "..".
  return path.slice(1).split('/').every(segment => SEGMENT.test(segment) && segment !== '.' && segment !== '..')
}

/** The host of a canonical entry. Only for a value `isStorageNodeBase` accepted. */
function hostOf(entry: string): string {
  return ENTRY.exec(entry)![2]!
}

/** True when `value` is a canonical node base URL. Never throws. */
export function isStorageNodeBase(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > MAX_STORAGE_NODE_URL_LENGTH) return false
  const m = ENTRY.exec(value)
  if (!m) return false
  const [, scheme, host, port, path] = m as unknown as [string, string, string, string | undefined, string]
  if (!isCanonicalHost(host) || !isCanonicalPath(path)) return false
  if (scheme === 'http' && !isPlainHttpHost(host)) return false
  if (port !== undefined) {
    if (!isCanonicalPort(port)) return false
    if ((scheme === 'https' && port === '443') || (scheme === 'http' && port === '80')) return false
  }
  // Belt to the grammar's braces: a WHATWG parser must read the entry the same way.
  try {
    const u = new URL(value)
    return `${u.protocol}//${u.host}${u.pathname === '/' ? '' : u.pathname}` === value
  } catch {
    return false
  }
}

/** True for a list the invitation may carry (0 to 8 canonical entries, one per host), including []. Never throws. */
export function isInvitationStorage(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length > MAX_INVITATION_STORAGE_NODES) return false
  // Hostile input may be sparse or hold holes: read by index, never by iterator.
  const hosts = new Set<string>()
  for (let i = 0; i < value.length; i++) {
    const entry: unknown = value[i]
    if (!isStorageNodeBase(entry)) return false
    hosts.add(hostOf(entry))
  }
  return hosts.size === value.length
}

/** Throws unless `nodes` is a list the invitation may carry; returns a copy. */
export function requireInvitationStorage(nodes: readonly string[]): string[] {
  if (!Array.isArray(nodes)) throw new Error('storage nodes must be a list')
  if (nodes.length > MAX_INVITATION_STORAGE_NODES) throw new Error(`a room can list at most ${MAX_INVITATION_STORAGE_NODES} storage nodes`)
  const hosts = new Set<string>()
  for (let i = 0; i < nodes.length; i++) {
    const entry: unknown = nodes[i]
    if (!isStorageNodeBase(entry)) throw new Error(`storage nodes must be canonical node URLs (https, or http only on this machine): ${String(entry)}`)
    const host = hostOf(entry)
    if (hosts.has(host)) throw new Error(`storage nodes must not share a host name: ${host}`)
    hosts.add(host)
  }
  return [...nodes]
}

function shorten(text: string): string {
  return text.length > 60 ? `${text.slice(0, 59)}…` : text
}

/**
 * The canonical form of an operator's URL, and its server. Lower-cases the
 * scheme and host, drops a default port and trailing slashes, and throws a
 * message fit to show an operator on anything the grammar refuses. It does not
 * refuse onion hosts: a keeper that cannot reach one says so itself.
 */
export function storageNodeFromBase(text: string): StorageNode {
  const typed = String(text).trim()
  let url: URL
  try { url = new URL(typed) } catch { throw new Error(`group node ${shorten(typed)}: not a URL`) }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`group node ${shorten(typed)}: only http and https nodes are supported in this version`)
  }
  // Read the pieces from the text as written, not from what the parser made of
  // them: it would quietly mend `127.1`, `0x7f.0.0.1`, a dot segment or a
  // percent-escape, and every one of those is refused here.
  const m = /^(https?):\/\/([^/?#]*)([^?#]*)([?#].*)?$/i.exec(typed)
  if (!m) throw new Error(`group node ${shorten(typed)}: not a URL`)
  const scheme = m[1]!.toLowerCase()
  const authority = m[2]!
  if (authority.includes('@')) throw new Error('group node: a URL with a user name or password is refused')
  if (m[4] !== undefined) throw new Error('group node: a URL with a query or fragment is refused')
  const colon = authority.lastIndexOf(':')
  const bracketed = authority.startsWith('[')
  const rawHost = colon === -1 || bracketed ? authority : authority.slice(0, colon)
  const port = colon === -1 || bracketed ? undefined : authority.slice(colon + 1)
  // Lower-case ASCII only: a non-ASCII letter must not fold into a legal host.
  const hostText = rawHost.replace(/[A-Z]/g, c => c.toLowerCase())
  if (!isCanonicalHost(hostText)) {
    throw new Error(`group node ${shorten(typed)}: the host name must be lower-case letters, digits, hyphens and dots (no IPv6 literal, no trailing dot)`)
  }
  if (scheme === 'http' && !isPlainHttpHost(hostText)) {
    throw new Error(`group node ${hostText}: plain http is only for a node on this machine (localhost or 127.x); use https so grants and revocations cannot be read or answered by somebody on the way`)
  }
  if (port !== undefined && !isCanonicalPort(port)) {
    throw new Error(`group node ${shorten(typed)}: the port must be a number from 1 to 65535, written without a leading zero`)
  }
  const path = m[3]!.replace(/\/+$/, '')
  if (!isCanonicalPath(path)) {
    throw new Error(`group node ${shorten(typed)}: the path may hold only letters, digits and . _ ~ - between slashes`)
  }
  const isDefaultPort = port !== undefined && ((scheme === 'https' && port === '443') || (scheme === 'http' && port === '80'))
  const base = `${scheme}://${hostText}${port === undefined || isDefaultPort ? '' : `:${port}`}${path}`
  if (base.length > MAX_STORAGE_NODE_URL_LENGTH) {
    throw new Error(`group node ${shorten(typed)}: the URL is longer than ${MAX_STORAGE_NODE_URL_LENGTH} characters`)
  }
  if (!isStorageNodeBase(base)) throw new Error(`group node ${shorten(typed)}: not a canonical node URL`)
  return { base, server: hostText }
}
