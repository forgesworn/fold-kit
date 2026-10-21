# Seal keys: healing after a device is copied

Status: 0.7.0. The first phase of KithMoot's key schedule parity plan
(`kithmoot/docs/2026-10-04-key-schedule-parity.md`).

## The problem

A device key does two jobs. It signs, and every rekey copy (1462, the `keys`
map) and every epoch grant (20469 from the authority, 20472 from a member)
was NIP-44-sealed to it. Whoever copies a device key opens every rekey and
grant after it, for as long as nobody notices and removes the device.

Rotating a receiving key that the device key signs heals nothing: the thief
holds the device key and signs their own rotation.

## The design

The receiving key rides in the device credential (kind 20460), which the
**participant** signs. The participant key usually lives in a signer (an
extension, a bunker, Heartwood) and not on the device, so it is the one thing
a device thief does not get.

- **Wire.** A credential may end with `["seal", <x-only pubkey>]`. The device
  mints a fresh seal key at each renewal. `createDeviceCredential({ seal })`
  appends the tag last, and refuses a value that is not a point on the curve.
  A credential with no seal tag is byte-identical to one from 0.6.0.
- **Sending.** A rekey copy and both grants are sealed to the seal key of the
  newest credential the sender holds for the device (`sealTarget`), falling
  back to the device key when that credential names none. The `keys` map stays
  keyed by device. A seal tag that is doubled or off the curve reads as
  unusable (`credentialSeal` returns null), and the sender seals to the device
  key rather than failing the whole rekey: only the participant can have
  signed it.
- **Keeping the secrets.** A device keeps its seal secrets as it keeps its
  device key. A device that reads a room again from the start (as a browser
  does, following the rekeys from epoch 0) opens each old copy with the seal
  key it was sealed to, so dropping them would leave it asking a desk for
  every epoch. Keeping them costs healing nothing: a thief who copies the
  device holds the seal keys minted up to then, which is what the newest of
  them already gave away, and none minted after. Retiring them belongs to
  forward secrecy (the plan's phase 2), alongside epoch secrets.
- **Never back to the device key.** `sealTarget` does not check expiry. A
  device quiet for longer than its credential still holds that seal key.
  Falling back to the device key would hand the copy to the thief.
- **Reading.** Every reader tries each seal key it holds, then the device key
  (`openSealed`). A rekey copy none of them opens reads as no copy: the rekey
  is still read (who was removed, whether the room closed), without a secret,
  and the device asks for the epoch.
- **Desks.** `hostRoomEpoch` and `hostMemberEpochDesk` take `credentialFor
  (device)`, the newest credential the room has seen for that device.
  `sealCredential` seals the answer to the newer of that and the one the
  request carries (`newerCredential`: later expiry, then later `created_at`),
  when the known one verifies for the same room, device and participant. A
  thief replaying the device's older, still-live credential is answered under
  the seal key the device has minted since.

`credentialFor` must be monotone. Roster entries are device-signed, so a
thief can publish one carrying the older credential. If that replaced the
newer one, the desk would seal to the copied seal key again.

## What healing covers

A thief who copied a device once holds the seal keys minted up to then, and
none minted after. They read until the next rekey and until the
copied credential lapses (up to twelve hours in KithMoot). After both, rekeys
are sealed where they cannot reach, and the desks answer the device's new
seal key.

Not covered here:

- **The link outlives healing.** The thief also holds epoch 0, which is the
  link, and can come back as a new participant. Healing turns an invisible
  reader into a visible stranger. Keeping them out as well needs the link
  replaced.
- **Rekeys.** Healing completes only at a rekey. KithMoot rekeys on removal
  today; scheduled rekeys are the plan's phase 2.
- **A participant key on the device** (a local nsec, no signer) heals only by
  removal: the thief can sign a fresh credential with a seal key of their own.
- **Secondary devices** whose credential another device mints, and which do
  not renew, carry no seal key and are sealed to as before.

## Compatibility

- Old senders ignore the tag and seal to the device key; new readers try the
  device key last, so they still read.
- New senders seal to the seal key only when the credential names one, and a
  client mints a seal key only once it reads seal-sealed copies, so an old
  reader never receives one.
- `decodeEpochRequest` and `decodeMemberEpochRequest` return what they did in
  0.6.0. The desks read the credential internally.

## One-time senders

Forward secrecy step 1 (KithMoot `docs/2026-10-06-key-schedule-next-steps.md`,
phase 2b). Every rekey copy and every authority grant used to be sealed from
the authority's long-lived key, so whoever later took that key could
recompute every past copy's conversation key and open it with nothing else.

With `oneTimeSender: true`, `encodeRekeyEvent` and `encodeEpochGrant` draw a
fresh key, seal every copy from it, name its public half in one
`["from", <x-only hex>]` tag, and zero the secret before signing. The event
is still signed by the authority, so the tag is the authority's word and a
forger's `from` is never read (the signer check comes first).

- A reader opens a copy with `sealSender(event)`: the single `from` tag's key,
  or the signer when there is none. More than one `from`, or one off the
  curve, is null: a rekey is then read without a secret (the device asks for
  the epoch), and a grant is refused.
- Taking the authority's key later no longer opens a copy. It still lets the
  taker sign new rekeys and grants; that is the healing question, not this
  one.
- A copy is still sealed to the recipient's seal key, so a past copy stays
  open to whoever holds that seal secret. Retiring seal keys older than the
  history window is step 3.
- The member grant (20472) has always been signed by a one-time key, and is
  unchanged.

**Readers first.** A reader older than 0.13.0 opens no copy from a one-time
key. For a rekey that costs a round trip (it asks for the epoch); for a grant
it costs the epoch. So `oneTimeSender` stays off in every writer until readers
have shipped on every client and had a release in the field. Off, every
event is byte-identical to before.

## Vectors

`vectors/seal-vectors.json` (generated by `scripts/generate-seal.mjs`,
checked by `vectors/verify-seal.test.ts`):

- `credential-seal-key`, `credential-without-seal`,
  `credential-seal-doubled`, `credential-seal-off-curve`;
- `newer-credential`;
- `rekey-seal` (a seal-keyed and a bare recipient; the renewed device, the
  thief and the bare device reading it), and `rekey-without-seal-keys`
  (byte-identical to a rekey with bare devices);
- `epoch-grant-seal` and `member-grant-seal` (the thief replays the copied
  credential; the desk seals to the renewed one).
- `rekey-one-time-sender` and `epoch-grant-one-time-sender` (the same rekey
  and grant from a one-time key; the authority's key no longer opens a copy),
  and the refusals `rekey-from-doubled`, `rekey-from-off-curve` and
  `epoch-grant-from-off-curve`.
