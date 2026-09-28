/** Hard bounds for network addresses carried by an untrusted room link or
 * descriptor. A handful of alternatives is useful; hundreds only spend
 * parser, DNS and connection resources. */
export const MAX_RELAY_HINTS = 8
export const MAX_ICE_HINTS = 8
export const MAX_NETWORK_HINT_LENGTH = 2048

const ICE_SCHEMES = ['stun:', 'stuns:', 'turn:', 'turns:']

function loopback(hostname: string): boolean {
  const host = hostname.toLowerCase()
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1'
}

/** Public relay hints must use encrypted WebSockets. Plain ws is retained
 * only for loopback development and tests, where TLS adds no transport
 * boundary. */
export function isSafeRelayUrl(raw: string): boolean {
  if (raw.length === 0 || raw.length > MAX_NETWORK_HINT_LENGTH) return false
  try {
    const parsed = new URL(raw)
    return parsed.protocol === 'wss:' || (parsed.protocol === 'ws:' && loopback(parsed.hostname))
  } catch {
    return false
  }
}

export function safeRelayUrls(raw: unknown): string[] {
  if (!Array.isArray(raw)) return []
  const out: string[] = []
  for (const value of raw) {
    if (typeof value !== 'string' || !isSafeRelayUrl(value) || out.includes(value)) continue
    if (out.length === MAX_RELAY_HINTS) break
    out.push(value)
  }
  return out
}

export function isSafeIceUrl(raw: string): boolean {
  if (raw.length === 0 || raw.length > MAX_NETWORK_HINT_LENGTH) return false
  const lower = raw.toLowerCase()
  return ICE_SCHEMES.some((scheme) => lower.startsWith(scheme))
}

export function safeIceUrls(raw: unknown): string[] {
  if (!Array.isArray(raw)) return []
  const out: string[] = []
  for (const value of raw) {
    if (typeof value !== 'string' || !isSafeIceUrl(value) || out.includes(value)) continue
    if (out.length === MAX_ICE_HINTS) break
    out.push(value)
  }
  return out
}

/** Refuse oversized arrays instead of silently turning an attacker's first
 * few entries into connection attempts. */
export function assertNetworkHintBounds(relays: unknown, ice: unknown): void {
  if (Array.isArray(relays) && relays.length > MAX_RELAY_HINTS) throw new Error('join URL carries too many relay hints')
  if (Array.isArray(ice) && ice.length > MAX_ICE_HINTS) throw new Error('join URL carries too many ICE hints')
}
