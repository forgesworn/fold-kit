import { describe, expect, it, vi } from 'vitest'
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure'
import { nip44 } from 'nostr-tools'
import { deriveEpoch, encodeRekeyEvent } from './epoch.js'
import { deriveRoom } from './room.js'
import { decodeRekeyEnvelope, decodeRekeyEventWithSigner, RekeySignerError } from './rekey-reader.js'

const secret = new Uint8Array(32).fill(7)
const authoritySk = new Uint8Array(32).fill(8)
const personSk = new Uint8Array(32).fill(9)
const person = getPublicKey(personSk)
const authority = getPublicKey(authoritySk)
const roomId = deriveRoom(secret).roomId
const current = deriveEpoch({ epoch: 0, secret })
const next = { epoch: 1, secret: new Uint8Array(32).fill(10) }
const options = { roomId, authority, current }
const create = (recipients = [person]) => encodeRekeyEvent({ ...options, authoritySk, recipients, next, removed: [], now: 1_800_000_000 })
const signer = () => ({ pubkey: person, nip44: { decrypt: vi.fn(async (peer: string, ciphertext: string) =>
  nip44.v2.decrypt(ciphertext, nip44.v2.utils.getConversationKey(personSk, peer))) } })

describe('signer rekey reading', () => {
  it('opens the existing v1 person copy once, without asking the signer to open the group envelope', async () => {
    const event = create()
    const identity = signer()
    const envelope = decodeRekeyEnvelope(event, options)!
    const notice = await decodeRekeyEventWithSigner(event, { ...options, signer: identity })
    expect(notice?.secret).toEqual(next.secret)
    expect(identity.nip44.decrypt).toHaveBeenCalledExactlyOnceWith(authority, envelope.sealedKeys[person])
    expect(envelope.notice).not.toHaveProperty('secret')
  })

  it('returns a valid copy-free notice without prompting, including for a closed room', async () => {
    const identity = signer()
    expect(await decodeRekeyEventWithSigner(create([]), { ...options, signer: identity })).toMatchObject({ epoch: 1, closed: false })
    const event = encodeRekeyEvent({ ...options, authoritySk, next, recipients: [person], removed: [], closed: true, now: 1_800_000_000 })
    expect(await decodeRekeyEventWithSigner(event, { ...options, signer: identity })).toMatchObject({ closed: true })
    expect(identity.nip44.decrypt).not.toHaveBeenCalled()
  })

  it('never prompts on forged, wrong-room, wrong-epoch or oversized outer input', async () => {
    const event = create()
    const identity = signer()
    for (const [input, opts] of [
      [{ ...event, sig: '0'.repeat(128) }, options],
      [event, { ...options, roomId: '0'.repeat(64) }],
      [event, { ...options, current: deriveEpoch(next) }],
      [{ ...event, content: 'x'.repeat(90_001) }, options],
    ] as const) expect(await decodeRekeyEventWithSigner(input, { ...opts, signer: identity })).toBeNull()
    expect(identity.nip44.decrypt).not.toHaveBeenCalled()
  })

  it('distinguishes signer refusal from invalid signed plaintext and does not mutate winner metadata', async () => {
    const event = create()
    const identity = signer()
    const refusal = new Error('Cancelled')
    identity.nip44.decrypt.mockRejectedValueOnce(refusal)
    await expect(decodeRekeyEventWithSigner(event, { ...options, signer: identity })).rejects.toMatchObject({ name: 'RekeySignerError', cause: refusal })
    expect(new RekeySignerError(refusal)).toBeInstanceOf(Error)
    identity.nip44.decrypt.mockResolvedValueOnce('{"v":1,"secret":"invalid"}')
    expect(await decodeRekeyEventWithSigner(event, { ...options, signer: identity })).toBeNull()
    expect(decodeRekeyEnvelope(event, options)?.notice.epoch).toBe(1)
  })

  it('refuses a malformed or ambiguously addressed body before any remote decrypt', async () => {
    const event = create()
    const original = JSON.parse(nip44.v2.decrypt(event.content, current.key))
    const identity = signer()
    for (const body of [
      { ...original, keys: [] },
      { ...original, keys: { ...original.keys, [person.toUpperCase()]: original.keys[person] } },
      { ...original, closed: true },
      { ...original, removed: [null] },
      { ...original, by: 'bad' },
    ]) {
      const changed = finalizeEvent({ kind: event.kind, created_at: event.created_at, tags: event.tags,
        content: nip44.v2.encrypt(JSON.stringify(body), current.key) }, authoritySk)
      expect(await decodeRekeyEventWithSigner(changed, { ...options, signer: identity })).toBeNull()
    }
    expect(identity.nip44.decrypt).not.toHaveBeenCalled()
  })
})
