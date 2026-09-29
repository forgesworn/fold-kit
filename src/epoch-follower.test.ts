import { describe, expect, it, vi } from 'vitest'
import { getPublicKey, type Event } from 'nostr-tools/pure'
import type { RelayTransport } from './transport.js'
import type { StoredEventQuery, StoredEventQueryResult } from './stored-query.js'
import { deriveEpoch, encodeRekeyEvent, type EpochKeys, type RoomEpoch } from './epoch.js'
import { EpochFollower, type EpochTransition, MAX_FOLLOWER_CANDIDATES } from './epoch-follower.js'

const authoritySk = Uint8Array.from({ length: 32 }, (_, i) => i + 1)
const authority = getPublicKey(authoritySk)
const root: RoomEpoch = { epoch: 0, secret: Uint8Array.from({ length: 32 }, (_, i) => i + 30) }
const roomId = deriveEpoch(root).id
const complete: StoredEventQueryResult = { queried: ['wss://one', 'wss://two'],
  eosed: ['wss://one'], unavailable: ['wss://two'] }

function epoch(number: number, salt: number): RoomEpoch {
  return { epoch: number, secret: Uint8Array.from({ length: 32 }, (_, i) => (i + salt) % 256) }
}

function rekey(current: RoomEpoch, next: RoomEpoch, now: number, closed = false): Event {
  return encodeRekeyEvent({ roomId, authoritySk, current: deriveEpoch(current), next,
    recipients: [], removed: [], closed, now })
}

function transport(): RelayTransport & { emit(event: Event): void } {
  let callback: ((event: Event) => void) | undefined
  return { publish: async () => {}, subscribe: (_filters, onEvent) => {
    callback = onEvent; return () => { callback = undefined }
  }, close: () => {}, emit: (event) => callback?.(event) }
}

function harness(initial = { epoch: 0, winningRekeyId: undefined as string | undefined }) {
  const keys = new Map<number, EpochKeys>([[0, deriveEpoch(root)]])
  const winners = new Map<number, string>()
  const secrets = new Map<string, RoomEpoch>()
  const events: Event[] = []
  const transitions: EpochTransition[] = []
  const live = transport()
  let queries = 0
  let persist: (change: EpochTransition) => Promise<void> = async (change) => {
    transitions.push(change)
    if (change.kind === 'replace') {
      for (const n of [...keys.keys()]) if (n >= change.invalidateFromEpoch!) keys.delete(n)
      for (const n of [...winners.keys()]) if (n >= change.invalidateFromEpoch!) winners.delete(n)
    }
    winners.set(change.notice.epoch, change.event.id)
    if (change.notice.secret) keys.set(change.notice.epoch, deriveEpoch({ epoch: change.notice.epoch,
      secret: change.notice.secret }))
    else keys.delete(change.notice.epoch)
  }
  let evidence: StoredEventQueryResult = complete
  const query: StoredEventQuery = async (filters, onEvent) => {
    queries++
    expect(filters).toEqual([{ kinds: [1462], authors: [authority], '#d': [roomId] }])
    for (const event of events) onEvent(event, 'wss://one')
    return evidence
  }
  const follower = new EpochFollower({ roomId, authority, transport: live, query, initial,
    epochKeys: (n) => keys.get(n), winningRekeyId: (n) => winners.get(n),
    openSecret: async (event) => secrets.get(event.id)?.secret,
    onTransition: (change) => persist(change) })
  return { follower, keys, winners, secrets, events, transitions, live,
    get queries() { return queries }, setEvidence(value: StoredEventQueryResult) { evidence = value },
    setPersist(fn: typeof persist) { persist = fn } }
}

describe('EpochFollower', () => {
  it('chooses the lowest complete-body id in either arrival order, independent of a recipient copy', async () => {
    const one = epoch(1, 50); const two = epoch(1, 60)
    const a = rekey(root, one, 100, true); const b = rekey(root, two, 101)
    const [lower, higher] = [a, b].sort((x, y) => x.id.localeCompare(y.id))
    for (const order of [[higher, lower], [lower, higher]]) {
      const h = harness()
      h.events.push(...order)
      h.secrets.set(higher.id, higher === a ? one : two)
      await h.follower.catchUp()
      expect(h.transitions).toHaveLength(1)
      expect(h.transitions[0]!.event.id).toBe(lower.id)
      expect(h.transitions[0]!.notice.secret).toBeUndefined()
      expect(h.winners.get(1)).toBe(lower.id)
    }
  })

  it('does not let a forged lower id win over a verified complete body', async () => {
    const next = epoch(1, 61); const event = rekey(root, next, 102)
    const forged = { ...event, id: '0'.repeat(64), sig: '0'.repeat(128) }
    const h = harness(); h.events.push(forged, event); h.secrets.set(event.id, next)
    await h.follower.catchUp()
    expect(h.transitions.map((change) => change.event.id)).toEqual([event.id])
  })

  it('does not let a forged copy of an authentic claimed id suppress the authentic event', async () => {
    const first = epoch(1, 62); const second = epoch(1, 63)
    const [lower, higher] = [rekey(root, first, 103), rekey(root, second, 104)]
      .sort((x, y) => x.id.localeCompare(y.id))
    const h = harness()
    h.events.push({ ...lower, sig: '0'.repeat(128) }, higher, lower)
    await h.follower.catchUp()
    expect(h.transitions.map((change) => change.event.id)).toEqual([lower.id])
  })

  it('retains a valid live lower fork that the completed stored query omits', async () => {
    const first = epoch(1, 64); const second = epoch(1, 65)
    const [lower, higher] = [rekey(root, first, 105), rekey(root, second, 106)]
      .sort((x, y) => x.id.localeCompare(y.id))
    const h = harness(); h.events.push(higher)
    h.follower.start()
    h.live.emit(lower)
    await h.follower.catchUp()
    expect(h.transitions.map((change) => change.event.id)).toEqual([lower.id])
    h.follower.close()
  })

  it('holds the barrier until real EOSE and shares concurrent calls', async () => {
    const next = epoch(1, 70); const event = rekey(root, next, 110)
    const h = harness(); h.events.push(event); h.secrets.set(event.id, next)
    let finish!: (result: StoredEventQueryResult) => void
    let queries = 0
    const waiting: StoredEventQuery = async (_filters, onEvent) => {
      queries++
      onEvent(event)
      return new Promise((resolve) => { finish = resolve })
    }
    const follower = new EpochFollower({ roomId, authority, transport: h.live, query: waiting,
      initial: { epoch: 0 }, epochKeys: (n) => h.keys.get(n), winningRekeyId: (n) => h.winners.get(n),
      openSecret: async () => next.secret, onTransition: async (change) => { h.transitions.push(change) } })
    const first = follower.catchUp(); const second = follower.catchUp()
    expect(first).toBe(second)
    expect(queries).toBe(1)
    await Promise.resolve()
    expect(h.transitions).toHaveLength(0)
    finish(complete)
    await first
    expect(h.transitions).toHaveLength(1)
  })

  it('uses a live event only as a hint to run the stored query', async () => {
    const next = epoch(1, 71); const event = rekey(root, next, 111)
    const h = harness(); h.events.push(event); h.secrets.set(event.id, next)
    h.follower.start()
    h.live.emit(event)
    await vi.waitFor(() => expect(h.transitions).toHaveLength(1))
    expect(h.queries).toBe(1)
    h.follower.close()
  })

  it('retries a rejected durable transition as an advance, without adopting it in memory', async () => {
    const next = epoch(1, 80); const event = rekey(root, next, 120)
    const h = harness(); h.events.push(event); h.secrets.set(event.id, next)
    h.setPersist(async () => { throw new Error('storage failure') })
    await expect(h.follower.catchUp()).rejects.toThrow('storage failure')
    expect(h.transitions).toHaveLength(0)
    expect(h.winners.has(1)).toBe(false)
    h.setPersist(async (change) => { h.transitions.push(change); h.winners.set(1, change.event.id) })
    await h.follower.catchUp()
    expect(h.transitions.map((change) => change.kind)).toEqual(['advance'])
  })

  it('keeps a valid winner after an operational secret-opening failure or missing copy', async () => {
    const next = epoch(1, 81); const event = rekey(root, next, 121, true)
    const h = harness(); h.events.push(event)
    let fail = true
    const follower = new EpochFollower({ roomId, authority, transport: h.live,
      query: async (_filters, onEvent) => { onEvent(event); return complete },
      initial: { epoch: 0 }, epochKeys: (n) => h.keys.get(n), winningRekeyId: (n) => h.winners.get(n),
      openSecret: async () => { if (fail) throw new Error('signer refused'); return undefined },
      onTransition: async (change) => { h.transitions.push(change) } })
    await expect(follower.catchUp()).rejects.toThrow('signer refused')
    expect(h.transitions).toHaveLength(0)
    fail = false
    await follower.catchUp()
    expect(h.transitions).toHaveLength(1)
    expect(h.transitions[0]!.notice).toMatchObject({ closed: true, epoch: 1 })
    expect(h.transitions[0]!.notice.secret).toBeUndefined()
  })

  it('replaces an earlier fork after descendant epochs, then refetches under the new parent', async () => {
    const first = epoch(1, 90); const second = epoch(1, 100)
    const a = rekey(root, first, 130); const b = rekey(root, second, 131)
    const [lower, higher] = [a, b].sort((x, y) => x.id.localeCompare(y.id))
    const lowSecret = lower === a ? first : second
    const highSecret = higher === a ? first : second
    const highChild = rekey(highSecret, epoch(2, 110), 132)
    const lowChildSecret = epoch(2, 120)
    const lowChild = rekey(lowSecret, lowChildSecret, 133)
    const h = harness()
    for (const [event, secret] of [[a, first], [b, second], [highChild, epoch(2, 110)],
      [lowChild, lowChildSecret]] as const) h.secrets.set(event.id, secret)
    h.events.push(higher, highChild)
    await h.follower.catchUp()
    expect(h.transitions.map((change) => change.notice.epoch)).toEqual([1, 2])
    h.events.push(lower, lowChild)
    await h.follower.catchUp()
    expect(h.transitions.map((change) => change.kind)).toEqual(['advance', 'advance', 'replace', 'advance'])
    expect(h.transitions[2]).toMatchObject({ previousWinnerId: higher.id, invalidateFromEpoch: 2 })
    expect(h.winners.get(1)).toBe(lower.id)
    expect(h.winners.get(2)).toBe(lowChild.id)
    expect(h.queries).toBeGreaterThanOrEqual(3)
  })

  it('refetches a live lower fork that arrives while the old winner is opening', async () => {
    const aSecret = epoch(1, 121); const bSecret = epoch(1, 122)
    const [lower, higher] = [rekey(root, aSecret, 134), rekey(root, bSecret, 135)]
      .sort((x, y) => x.id.localeCompare(y.id))
    const h = harness(); h.events.push(higher)
    let release!: () => void
    let opened = false
    const follower = new EpochFollower({ roomId, authority, transport: h.live,
      query: async (_filters, onEvent) => { for (const event of h.events) onEvent(event); return complete },
      initial: { epoch: 0 }, epochKeys: (n) => h.keys.get(n), winningRekeyId: (n) => h.winners.get(n),
      openSecret: async () => { if (!opened) { opened = true; await new Promise<void>((resolve) => { release = resolve }) }
        return aSecret.secret },
      onTransition: async (change) => { h.transitions.push(change) } })
    follower.start()
    const pending = follower.catchUp()
    await Promise.resolve(); await Promise.resolve()
    expect(opened).toBe(true)
    h.events.push(lower); h.live.emit(lower); release()
    await pending
    expect(h.transitions.map((change) => change.event.id)).toEqual([lower.id])
    follower.close()
  })

  it('uses durable historical parent keys and winner ids after a restart', async () => {
    const aSecret = epoch(1, 123); const bSecret = epoch(1, 124)
    const [lower, higher] = [rekey(root, aSecret, 136), rekey(root, bSecret, 137)]
      .sort((x, y) => x.id.localeCompare(y.id))
    const lowSecret = lower.created_at === 136 ? aSecret : bSecret
    const highSecret = higher.created_at === 136 ? aSecret : bSecret
    const highChildSecret = epoch(2, 125)
    const highChild = rekey(highSecret, highChildSecret, 138)
    const lowChildSecret = epoch(2, 126)
    const lowChild = rekey(lowSecret, lowChildSecret, 139)
    const h = harness({ epoch: 2, winningRekeyId: highChild.id })
    h.keys.set(1, deriveEpoch(highSecret)); h.keys.set(2, deriveEpoch(highChildSecret))
    h.winners.set(1, higher.id); h.winners.set(2, highChild.id)
    h.events.push(higher, highChild, lower, lowChild)
    h.secrets.set(lower.id, lowSecret); h.secrets.set(lowChild.id, lowChildSecret)
    await h.follower.catchUp()
    expect(h.transitions.map((change) => change.kind)).toEqual(['replace', 'advance'])
    expect(h.winners.get(1)).toBe(lower.id)
    expect(h.winners.get(2)).toBe(lowChild.id)
  })

  it('rechecks a lower live fork before advancing on the old branch after a durable callback', async () => {
    const first = epoch(1, 127); const second = epoch(1, 128)
    const [lower, higher] = [rekey(root, first, 160), rekey(root, second, 161)]
      .sort((x, y) => x.id.localeCompare(y.id))
    const highSecret = higher.created_at === 160 ? first : second
    const highChild = rekey(highSecret, epoch(2, 129), 162)
    const h = harness(); h.events.push(higher, highChild)
    h.secrets.set(lower.id, lower.created_at === 160 ? first : second)
    h.secrets.set(higher.id, highSecret)
    h.secrets.set(highChild.id, epoch(2, 129))
    let started!: () => void; let release!: () => void
    const entered = new Promise<void>((resolve) => { started = resolve })
    const hold = new Promise<void>((resolve) => { release = resolve })
    h.setPersist(async (change) => {
      h.transitions.push(change)
      if (h.transitions.length === 1) { started(); await hold }
      if (change.kind === 'replace') {
        h.keys.delete(2); h.winners.delete(2)
      }
      h.winners.set(change.notice.epoch, change.event.id)
      if (change.notice.secret) h.keys.set(change.notice.epoch,
        deriveEpoch({ epoch: change.notice.epoch, secret: change.notice.secret }))
    })
    h.follower.start()
    const pending = h.follower.catchUp()
    await entered
    h.live.emit(lower) // deliberately absent from every stored-query result
    release()
    await pending
    expect(h.transitions.map((change) => [change.kind, change.notice.epoch])).toEqual([
      ['advance', 1], ['replace', 1],
    ])
    h.follower.close()
  })

  it('refuses partial source outcomes and bounded overflow before any transition', async () => {
    const next = epoch(1, 140); const event = rekey(root, next, 140)
    const h = harness(); h.events.push(event); h.secrets.set(event.id, next)
    h.setEvidence({ queried: ['wss://one', 'wss://two'], eosed: [], unavailable: ['wss://two'] })
    await expect(h.follower.catchUp()).rejects.toThrow('real EOSE')
    h.setEvidence({ queried: ['wss://one', 'wss://two'], eosed: ['wss://one'], unavailable: [] })
    await expect(h.follower.catchUp()).rejects.toThrow('every queried source')
    expect(h.transitions).toHaveLength(0)
    h.setEvidence(complete)
    for (let i = 0; i <= MAX_FOLLOWER_CANDIDATES; i++) h.events.push({ ...event,
      id: i.toString(16).padStart(64, '0'), sig: '0'.repeat(128) })
    await expect(h.follower.catchUp()).rejects.toThrow('candidate bound exceeded')
    expect(h.transitions).toHaveLength(0)
  })

  it('prunes rejected live traffic so a later clean stored query can recover', async () => {
    const next = epoch(1, 141); const valid = rekey(root, next, 141)
    const h = harness(); h.follower.start()
    for (let i = 0; i < MAX_FOLLOWER_CANDIDATES; i++) h.live.emit({ ...valid,
      id: i.toString(16).padStart(64, '0'), sig: '0'.repeat(128) })
    await h.follower.catchUp()
    expect(h.transitions).toHaveLength(0)
    h.events.push(valid); h.secrets.set(valid.id, next)
    await h.follower.catchUp()
    expect(h.transitions.map((change) => change.event.id)).toEqual([valid.id])
    h.follower.close()
  })

  it('recovers a live overflow only after every queried source has completed refetch', async () => {
    const next = epoch(1, 142); const valid = rekey(root, next, 142)
    const h = harness(); h.follower.start()
    for (let i = 0; i <= MAX_FOLLOWER_CANDIDATES + 1; i++) h.live.emit({ ...valid,
      id: i.toString(16).padStart(64, '0'), sig: '0'.repeat(128) })
    await expect(h.follower.catchUp()).rejects.toThrow('complete stored refetch')
    h.setEvidence({ queried: ['wss://one', 'wss://two'],
      eosed: ['wss://one', 'wss://two'], unavailable: [] })
    h.events.push(valid); h.secrets.set(valid.id, next)
    await h.follower.catchUp()
    expect(h.transitions.map((change) => change.event.id)).toEqual([valid.id])
    h.follower.close()
  })

  it('never calls the transition after close, even if a query ignores cancellation', async () => {
    const next = epoch(1, 150); const event = rekey(root, next, 150)
    let finish!: (result: StoredEventQueryResult) => void
    const h = harness()
    const follower = new EpochFollower({ roomId, authority, transport: h.live,
      query: async (_filters, onEvent) => { onEvent(event); return new Promise((resolve) => { finish = resolve }) },
      initial: { epoch: 0 }, epochKeys: (n) => h.keys.get(n), winningRekeyId: (n) => h.winners.get(n),
      openSecret: async () => next.secret, onTransition: async (change) => { h.transitions.push(change) } })
    const pending = follower.catchUp()
    follower.close(); finish(complete)
    await expect(pending).rejects.toThrow('cancelled')
    expect(h.transitions).toHaveLength(0)
  })

  it('does not call the transition when closed while opening the chosen copy', async () => {
    const next = epoch(1, 151); const event = rekey(root, next, 151)
    const h = harness()
    let finish!: (secret: Uint8Array) => void
    const follower = new EpochFollower({ roomId, authority, transport: h.live,
      query: async (_filters, onEvent) => { onEvent(event); return complete },
      initial: { epoch: 0 }, epochKeys: (n) => h.keys.get(n), winningRekeyId: (n) => h.winners.get(n),
      openSecret: async () => new Promise((resolve) => { finish = resolve }),
      onTransition: async (change) => { h.transitions.push(change) } })
    const pending = follower.catchUp()
    await Promise.resolve(); await Promise.resolve()
    expect(finish).toBeTypeOf('function')
    follower.close(); finish(next.secret)
    await expect(pending).rejects.toThrow('cancelled')
    expect(h.transitions).toHaveLength(0)
  })
})
