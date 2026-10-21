import { describe, expect, it } from 'vitest'
import {
  isInvitationStorage,
  isStorageNodeBase,
  MAX_INVITATION_STORAGE_NODES,
  MAX_STORAGE_NODE_URL_LENGTH,
  requireInvitationStorage,
  storageNodeFromBase,
} from './invitation-storage.js'
import { ACCEPTS, ONION, REFUSALS } from '../test/storage-fixtures.js'

describe('storage node base URLs', () => {
  it.each(ACCEPTS)('accepts %s and names %s as its server', (entry, server) => {
    expect(isStorageNodeBase(entry)).toBe(true)
    expect(storageNodeFromBase(entry)).toEqual({ base: entry, server })
  })

  it('accepts exactly 256 characters and no more', () => {
    const at = `https://example.net/${'a'.repeat(MAX_STORAGE_NODE_URL_LENGTH - 'https://example.net/'.length)}`
    expect(at).toHaveLength(MAX_STORAGE_NODE_URL_LENGTH)
    expect(isStorageNodeBase(at)).toBe(true)
    expect(isStorageNodeBase(`${at}a`)).toBe(false)
  })

  it.each(REFUSALS)('refuses %s', (_label, entry) => {
    expect(isStorageNodeBase(entry)).toBe(false)
    expect(isInvitationStorage([entry])).toBe(false)
    expect(() => requireInvitationStorage([entry])).toThrow(/storage node/)
  })

  it.each([undefined, null, 7, {}, [], ['https://example.net'], new String('https://example.net')])('isStorageNodeBase refuses a non-string: %s', value => {
    expect(isStorageNodeBase(value)).toBe(false)
  })

  it('agrees with the grammar for every accepted row and no refused row', () => {
    for (const [entry] of ACCEPTS) expect(isStorageNodeBase(entry)).toBe(true)
    for (const [, entry] of REFUSALS) expect(isStorageNodeBase(entry)).toBe(false)
  })

  it('never throws on hostile input', () => {
    for (const value of ['\0', 'https://\0', 'https://example.net/\n', 'https://example.net\n', 'https://ex\tample.net', '\u0000'.repeat(1_000), 'https://' + 'a.'.repeat(500)]) {
      expect(isStorageNodeBase(value)).toBe(false)
    }
  })
})

describe('the storage list', () => {
  it('accepts 0 to 8 entries on distinct hosts, in order', () => {
    expect(isInvitationStorage([])).toBe(true)
    const eight = Array.from({ length: MAX_INVITATION_STORAGE_NODES }, (_, i) => `https://node${i}.example.net`)
    expect(isInvitationStorage(eight)).toBe(true)
    expect(requireInvitationStorage(eight)).toEqual(eight)
    expect(requireInvitationStorage([])).toEqual([])
    expect(requireInvitationStorage(['https://b.example.net', 'https://a.example.net'])).toEqual(['https://b.example.net', 'https://a.example.net'])
  })

  it('returns a copy', () => {
    const list = ['https://a.example.net']
    const copy = requireInvitationStorage(list)
    expect(copy).not.toBe(list)
    expect(copy).toEqual(list)
  })

  it.each<[string, unknown, RegExp | null]>([
    ['not an array', 'https://example.net', null],
    ['null', null, null],
    ['an object', { 0: 'https://example.net', length: 1 }, null],
    ['a number in the list', ['https://example.net', 7], /canonical node URLs \(https, or http only on this machine\): 7/],
    ['nine entries', Array.from({ length: 9 }, (_, i) => `https://node${i}.example.net`), /at most 8 storage nodes/],
    ['two ports on one host', ['https://example.net', 'https://example.net:8443'], /share a host name: example\.net/],
    ['the same entry twice', ['https://example.net', 'https://example.net'], /share a host name: example\.net/],
    ['a hole', [, 'https://example.net'] as unknown[], null],
  ])('refuses %s', (_label, value, message) => {
    expect(isInvitationStorage(value)).toBe(false)
    if (message) expect(() => requireInvitationStorage(value as string[])).toThrow(message)
    else expect(() => requireInvitationStorage(value as string[])).toThrow(/storage nodes/)
  })
})

describe('storageNodeFromBase', () => {
  it('canonicalises case, a default port and trailing slashes, and trims', () => {
    expect(storageNodeFromBase('HTTPS://Grove.Example.NET:443/')).toEqual({ base: 'https://grove.example.net', server: 'grove.example.net' })
    expect(storageNodeFromBase('  https://example.net/wb//  ')).toEqual({ base: 'https://example.net/wb', server: 'example.net' })
    expect(storageNodeFromBase('http://LOCALHOST:80')).toEqual({ base: 'http://localhost', server: 'localhost' })
    expect(storageNodeFromBase('https://example.net:8443/')).toEqual({ base: 'https://example.net:8443', server: 'example.net' })
  })

  it('does not refuse an onion host (the keeper does)', () => {
    expect(storageNodeFromBase(`http://${ONION}/`)).toEqual({ base: `http://${ONION}`, server: ONION })
  })

  it.each<[string, string]>([
    ['banana', 'group node banana: not a URL'],
    ['', 'group node : not a URL'],
    ['https://example.net:65536', 'group node https://example.net:65536: not a URL'],
    ['ftp://example.net', 'group node ftp://example.net: only http and https nodes are supported in this version'],
    ['https://user:pw@example.net', 'group node: a URL with a user name or password is refused'],
    ['https://user@example.net', 'group node: a URL with a user name or password is refused'],
    ['https://example.net/?x=1', 'group node: a URL with a query or fragment is refused'],
    ['https://example.net/#x', 'group node: a URL with a query or fragment is refused'],
    ['https://example.net?', 'group node: a URL with a query or fragment is refused'],
    ['https://[::1]/', 'group node https://[::1]/: the host name must be lower-case letters, digits, hyphens and dots (no IPv6 literal, no trailing dot)'],
    ['https://example.net./', 'group node https://example.net./: the host name must be lower-case letters, digits, hyphens and dots (no IPv6 literal, no trailing dot)'],
    ['http://127.1', 'group node http://127.1: the host name must be lower-case letters, digits, hyphens and dots (no IPv6 literal, no trailing dot)'],
    ['http://0x7f.0.0.1', 'group node http://0x7f.0.0.1: the host name must be lower-case letters, digits, hyphens and dots (no IPv6 literal, no trailing dot)'],
    ['https://exämple.net', 'group node https://exämple.net: the host name must be lower-case letters, digits, hyphens and dots (no IPv6 literal, no trailing dot)'],
    ['http://example.org', 'group node example.org: plain http is only for a node on this machine (localhost or 127.x); use https so grants and revocations cannot be read or answered by somebody on the way'],
    ['https://example.net/a%20b', 'group node https://example.net/a%20b: the path may hold only letters, digits and . _ ~ - between slashes'],
    ['https://example.net/a/../b', 'group node https://example.net/a/../b: the path may hold only letters, digits and . _ ~ - between slashes'],
    ['https://example.net/a//b', 'group node https://example.net/a//b: the path may hold only letters, digits and . _ ~ - between slashes'],
    ['https://example.net:08080', 'group node https://example.net:08080: the port must be a number from 1 to 65535, written without a leading zero'],
  ])('refuses %s with an operator message', (text, message) => {
    expect(() => storageNodeFromBase(text)).toThrow(new Error(message))
  })

  it('refuses a URL over 256 characters once canonical, shortening the text it quotes to 60', () => {
    const text = `https://example.net/${'a'.repeat(240)}`
    expect(() => storageNodeFromBase(text)).toThrow(`group node ${text.slice(0, 59)}…: the URL is longer than 256 characters`)
    // Trailing slashes do not count: this one is 256 once canonical.
    expect(storageNodeFromBase(`https://example.net/${'a'.repeat(236)}///`).base).toHaveLength(256)
  })

  it('canonical output is always a canonical entry', () => {
    for (const text of ['HTTPS://Example.net:443//', 'http://127.0.0.1:80/', 'https://192.0.2.10:8443/a/b///', ...ACCEPTS.map(([entry]) => entry)]) {
      expect(isStorageNodeBase(storageNodeFromBase(text).base)).toBe(true)
    }
  })

  it('never returns a base for an entry the grammar refuses', () => {
    for (const [, entry] of REFUSALS) {
      let base: string | undefined
      try { base = storageNodeFromBase(entry).base } catch { /* refused, as it should be */ }
      if (base !== undefined) expect(isStorageNodeBase(base)).toBe(true)
    }
  })
})
