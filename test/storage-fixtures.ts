import { MAX_STORAGE_NODE_URL_LENGTH } from '../src/invitation-storage.js'

/** A made-up onion v3 host: 56 characters of a-z and 2-7. */
export const ONION = 'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion'

/** Canonical entries and the `server` each implies. */
export const ACCEPTS: ReadonlyArray<readonly [string, string]> = [
  ['https://grove.example.net', 'grove.example.net'],
  ['https://grove.example.net:8443', 'grove.example.net'],
  ['https://example.net/wb/node-1', 'example.net'],
  ['http://localhost:3000', 'localhost'],
  ['http://127.0.0.1:8080', '127.0.0.1'],
  [`http://${ONION}`, ONION],
  ['https://192.0.2.10', '192.0.2.10'],
  ['https://localhost', 'localhost'],
  ['https://example.net:65535', 'example.net'],
  ['http://127.255.255.254', '127.255.255.254'],
  ['https://example.net/a.b/c_d/e~f/...', 'example.net'],
  // Rule 4 applies to the last label only, and a path keeps its case.
  ['https://0x.example.net', '0x.example.net'],
  ['https://example.net/WB', 'example.net'],
  // `xn--` labels are plain letters, digits and hyphens to the grammar, valid Punycode or not.
  ['https://xn--bcher-kva.example', 'xn--bcher-kva.example'],
  ['https://xn--a.example.net', 'xn--a.example.net'],
]

/** Entries that are not canonical, one fault each. */
export const REFUSALS: ReadonlyArray<readonly [string, string]> = [
  ['trailing slash', 'https://example.net/wb/'],
  ['root slash', 'https://grove.example.net/'],
  ['upper-case host', 'https://Grove.Example.net'],
  ['upper-case scheme', 'HTTPS://grove.example.net'],
  ['default port 443', 'https://grove.example.net:443'],
  ['port 80 on http', 'http://localhost:80'],
  ['port with a leading zero', 'https://grove.example.net:08080'],
  ['port 0', 'https://grove.example.net:0'],
  ['port 65536', 'https://grove.example.net:65536'],
  ['an empty port', 'https://grove.example.net:'],
  ['a query', 'https://grove.example.net?x=1'],
  ['a fragment', 'https://grove.example.net#x'],
  ['user info', 'https://user:pw@grove.example.net'],
  ['http on a public host', 'http://grove.example.net'],
  ['http on a subdomain of localhost', 'http://a.localhost'],
  ['a ws scheme', 'ws://grove.example.net'],
  ['an IPv6 literal', 'https://[::1]'],
  ['a trailing dot', 'https://grove.example.net.'],
  ['a short IPv4 form', 'http://127.1'],
  ['a hex IPv4 form', 'http://0x7f.0.0.1'],
  ['an octet with a leading zero', 'http://127.000.0.1'],
  ['an octet over 255', 'https://192.0.2.256'],
  ['a numeric last label with three octets', 'https://example.net.1'],
  ['a hex last label with no digits after 0x', 'https://example.0x'],
  ['a hex last label that is not an octet', 'https://a.b.c.0x1'],
  ['a single numeric label', 'https://4294967295'],
  ['a percent-encoded path', 'https://example.net/a%2Fb'],
  ['a dot segment', 'https://example.net/a/./b'],
  ['a dot-dot segment', 'https://example.net/a/../b'],
  ['an empty segment', 'https://example.net//x'],
  ['a space in the path', 'https://example.net/a b'],
  ['a non-ASCII host', 'https://exämple.net'],
  ['a Kelvin sign in the host', 'https://Kexample.net'],
  ['a label starting with a hyphen', 'https://-grove.example.net'],
  ['a label ending with a hyphen', 'https://grove-.example.net'],
  ['an underscore in the host', 'https://gro_ve.example.net'],
  ['a 64 character label', `https://${'a'.repeat(64)}.example.net`],
  ['257 characters', `https://example.net/${'a'.repeat(MAX_STORAGE_NODE_URL_LENGTH + 1 - 'https://example.net/'.length)}`],
  ['a trailing line end after the host', 'https://grove.example.net\n'],
  ['a trailing line end after the path', 'https://example.net/wb\n'],
  ['a leading space', ' https://grove.example.net'],
  ['a trailing space', 'https://grove.example.net '],
  ['an empty string', ''],
  ['no scheme', 'example.net'],
]
