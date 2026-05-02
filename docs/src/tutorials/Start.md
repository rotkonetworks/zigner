# Getting started

This walks through setting up Zigner for **Zcash** as the primary use case.
The same device handles Penumbra and Substrate too.

## 1. Set up the device

Start from a phone you don't use for anything else. The strongest
configuration is a Pixel 8 or later running GrapheneOS — see
[Security and Privacy](../about/Security-And-Privacy.md) for why.

1. Factory reset the phone.
2. Install your OS (GrapheneOS recommended). Verify boot chain.
3. Set a strong device passcode. Don't rely on biometrics alone — they
   can be compelled.
4. Install Zigner from the [GitHub release](https://github.com/rotkonetworks/zigner/releases).
   Verify both the SHA256 checksum and the ssh signature on `SHA256SUMS`.
5. Enable airplane mode. Disable WiFi, Bluetooth, NFC, and cellular.
   Physically removing wireless hardware is better if your device allows
   it. **The user is responsible for the air gap** — Zigner's connectivity
   detection is informational, not a guarantee.

Do all of this *before* launching the Zigner app for the first time.

## 2. Create or recover a seed

On first launch, Zigner walks through accepting terms, then prompts to
create a key set.

- **New user**: let Zigner generate a fresh BIP-39 seed phrase using the
  built-in randomness. Back it up on paper. Store the paper somewhere
  physically secure. Anyone with this phrase has full control of every
  account derived from it. If you lose the phrase, the keys are gone.
- **Recovering**: switch to recovery mode and enter your existing seed
  phrase. **Do not type a custom seed phrase unless it was generated
  with proper randomness** — security depends entirely on this.

When you tap *Create*, the device's secure element prompts you to
authenticate. From this point on, every operation that touches a private
key requires authentication.

## 3. Pair with Zafu (Zcash hot wallet)

Zigner holds the spending key. Zafu holds only the viewing key and
constructs transactions.

1. In Zigner, open the key set and tap *Export* on the Zcash account.
   You'll see a UFVK QR code (ZIP-316 format, encoded as UR).
2. In Zafu, choose *Import watch-only* and scan the QR.
3. Zafu syncs notes against the chain via your indexer (zidecar in the
   Rotko stack).
4. Zafu exports the verified note bundle to Zigner as a `ur:zcash-notes`
   QR. Zigner verifies the merkle paths and stores the anchor as the
   trusted root for future spends.

Once paired, your day-to-day flow for sending ZEC is:

1. In Zafu, build the transaction. Zafu shows a PCZT as animated QR.
2. In Zigner, scan the QR. The review screen shows recipient, amount,
   fee, and any anchor / known-spend warnings.
3. **Tap the recipient address to reveal the full string**. Read it
   character by character against what you intended.
4. Approve. Zigner signs and shows a signature QR.
5. Zafu scans the signature QR and broadcasts.

If anything is wrong (anchor mismatch, unknown spends, value out of
range), Zigner refuses to sign. There is no override.

## 4. Optional: FROST multisig

To run Orchard spends as a *t-of-n* threshold multisig, see the
[FROST FAQ section](../about/FAQ.md#frost-multisig). DKG and signing
both happen between Zigner and Zafu over animated QR codes — no relay
server needed.

Once any device has participated in a FROST group, a sticky flag is
set: the device permanently requires anchor attestation on every note
import, defending against a compromised hot wallet on a future
single-signer setup.

## 5. Optional: Hot wallet for daily spending

Zigner can derive a 12-word BIP-39 hot wallet mnemonic from the master
seed and export it as `ur:zafu-hot-wallet` for use in Zafu pro. Useful
for small daily transactions where you don't want to keep pulling out
the cold device. The hot wallet is *not* an isolated security boundary
— if the hot device is compromised, rotate.

## 6. Optional: ZID auth

For OAuth-less login on services that support the ZID challenge
protocol (Zafu pro and others), Zigner signs site-scoped ed25519
challenges. Each origin gets a different public key — there's no
cross-site correlation by default.

## 7. Backup

Once you have key sets, FROST groups, and contacts you care about,
export an encrypted backup:

1. *Settings → Backup → Export*.
2. Zigner displays the backup as `ur:zigner-backup` animated QR.
3. Save those frames somewhere you can read them back later (paper QR
   booklet, second cold device, or print and store with the seed
   phrase paper).

The backup is encrypted with a key derived from your seed phrase. To
restore, you need both the seed phrase and the backup QR. The seed
phrase alone restores only the bare key sets.
