import type { Event } from 'nostr-tools/pure'
import type { Filter } from 'nostr-tools/filter'

/** A stored query ends only after every queried source has sent a real EOSE or failed. */
export interface StoredEventQueryResult {
  queried: readonly string[]
  /** Actual relay EOSE messages; a local deadline must never appear here. */
  eosed: readonly string[]
  unavailable: readonly string[]
}

export type StoredEventQuery = (
  filters: Filter[], onEvent: (event: Event, via?: string) => void, signal?: AbortSignal,
) => Promise<StoredEventQueryResult>

/** Check the adapter's completion evidence before using any partial event result. */
export function assertCompleteStoredQuery(result: StoredEventQueryResult): void {
  if (!result || !Array.isArray(result.queried) || !Array.isArray(result.eosed) || !Array.isArray(result.unavailable)) {
    throw new Error('stored query returned no source outcomes')
  }
  const valid = (list: readonly string[]) => Array.from(list).every((source) => typeof source === 'string' && source.length > 0) &&
    new Set(list).size === list.length
  if (!valid(result.queried) || !valid(result.eosed) || !valid(result.unavailable) ||
      result.queried.length === 0 || result.eosed.length === 0) {
    throw new Error('stored query lacks a real EOSE or has invalid source outcomes')
  }
  const outcomes = [...result.eosed, ...result.unavailable]
  if (new Set(outcomes).size !== outcomes.length || outcomes.length !== result.queried.length ||
      outcomes.some((source) => !result.queried.includes(source))) {
    throw new Error('stored query did not report every queried source exactly once')
  }
}
