# Sync verified notes to your signer

Zigner is air-gapped — it can't see the chain. The verified-notes sync gives it
a snapshot of which notes you own (by nullifier) and your balance, so it can
recognise your own spends and warn you when a transaction spends value it
hasn't verified. Without a sync, Zigner reviews transactions Keystone-style
(recipient + amount + fee only); it just can't add the extra "is this spending
my notes?" check.

## When to sync

- **After pairing** — once you've imported your watch-only wallet into Zafu.
- **After receiving** funds you intend to spend from Zigner.
- **After sending** — the change from a send is a *new* note Zigner hasn't seen.
  Until you re-sync, the next spend of that change shows as unverified (Zigner
  warns you). Re-syncing clears it. This is expected, not an error.

## How to sync (Zafu → Zigner)

1. In **Zafu**, let the Zcash wallet finish syncing against your indexer.
2. Open **Settings → Wallets**, expand your Zigner (watch-only) Zcash wallet,
   and tap **Sync balance to Zigner**.
3. Zafu builds the verified-note bundle and displays it as an animated QR
   (`zt:zcash-notes`). Against a zidecar indexer it also attaches an ed25519
   anchor attestation so a FROST device will accept it.
4. On **Zigner**, open the scanner and point it at the animated QR. Hold steady
   — it cycles through many frames; the counter shows how many it has captured.
5. Zigner verifies each note's merkle path against the anchor (and the
   attestation, if your device requires one), then shows the verified balance
   and note count. Tap **Done**.

## What the spend labels mean (when you later sign)

On the PCZT review screen each spend is labelled:

- **Verified spend** (gold) — the note is in your last synced set.
- **Dummy (privacy padding)** (grey) — a zero-value Orchard padding action.
  Harmless; every Orchard transaction has at least two actions.
- **Unknown spend — verify carefully** (red) — real value is being spent from
  notes this device hasn't verified.

If the transaction spends value that isn't in your verified set, Zigner first
shows an **Unrecognized spends** page with **Acknowledge and proceed**. This is
a *soft* warning, not a block — it's common right after a send, because your
change note isn't synced yet. Re-sync to clear it, or proceed if you've
reviewed the recipient and amount and trust the transaction.

A device that has never synced notes shows none of this — it falls back to the
plain recipient/amount/fee review.

## Attestation and indexers

Once a device has joined a [FROST](../about/FAQ.md#frost-multisig) group it
*permanently* requires the anchor attestation on every note import. A plain
lightwalletd indexer can't produce one, so use a zidecar-backed indexer (the
Rotko stack) for those devices. A single-signer device that has never touched
FROST accepts unattested bundles.
