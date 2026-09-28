import { describe, it, expect } from 'vitest'
import { deriveRoom } from './room.js'
import { deriveChannel, MAX_CHANNEL_NAME_LENGTH } from './channel.js'

// Adapted from KithMoot's src/chat.test.ts "channels" describe block: only
// the two cases that exercise `deriveChannel` itself, with no dependency on
// `ChatLog` or the chat event codecs (which stay in KithMoot - see
// docs/plans/2026-09-28-circle-kit-extraction.md §1.1 in the girnel
// repository).

function fixture() {
  const secret = new Uint8Array(32).fill(7)
  return deriveRoom(secret)
}

describe('channels', () => {
  it('derives a channel id and key from the room key, and never from the room id', () => {
    const { roomId, roomKey } = fixture()
    const agents = deriveChannel(roomId, roomKey, 'agents')
    expect(agents.id).toMatch(/^[0-9a-f]{64}$/)
    expect(agents.id).not.toBe(roomId)
    expect(agents.key).not.toEqual(roomKey)
    expect(agents.key.length).toBe(32)
    // The same room, a different key: a different channel, so a party that
    // holds the room id alone can find neither.
    const other = deriveChannel(roomId, new Uint8Array(32).fill(8), 'agents')
    expect(other.id).not.toBe(agents.id)
    // Unnamed is the main chat, byte for byte.
    expect(deriveChannel(roomId, roomKey)).toEqual({ id: roomId, key: roomKey })
    // Two names, two channels.
    expect(deriveChannel(roomId, roomKey, 'transcript').id).not.toBe(agents.id)
  })

  it('refuses a channel name that is empty or absurdly long', () => {
    const { roomId, roomKey } = fixture()
    expect(() => deriveChannel(roomId, roomKey, '')).toThrow()
    expect(() => deriveChannel(roomId, roomKey, 'x'.repeat(MAX_CHANNEL_NAME_LENGTH + 1))).toThrow()
  })
})
