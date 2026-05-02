# FAQ

- [General](#general)
- [Zcash](#zcash)
- [FROST multisig](#frost-multisig)
- [Anchor attestation](#anchor-attestation)
- [ZID auth](#zid-auth)
- [Hot wallet (Zafu pro)](#hot-wallet-zafu-pro)
- [Encrypted backup](#encrypted-backup)
- [Penumbra](#penumbra)
- [Substrate](#substrate)
- [Seeds and keys](#seeds-and-keys)

## General

### What is Zigner?

An air-gapped cold signer focused on Zcash, with Penumbra and Substrate
also supported. It holds private keys on an offline phone and signs
transactions presented as QR codes. It never touches a network.

### What does it protect against?

A compromised hot wallet. Even if Zafu, Zashi, Prax, or Polkadot.js is
backdoored, the attacker cannot extract your spending key — it never
leaves the signing device. They can present a malicious transaction,
but Zigner displays the decoded contents and enforces several
cryptographic invariants before signing.

### What does it NOT protect against?

- You approving a transaction you didn't read
- Physical access to the unlocked device
- A supply chain attack on Zigner itself (verify reproducible builds and
  the released `SHA256SUMS` ssh signature)
- Side channels on the phone hardware (EM, power analysis)

### How does the device communicate?

QR codes only. The hot wallet encodes an unsigned transaction as a QR
code (animated UR if multipart). Zigner scans it, displays the parsed
contents, signs if approved, and shows a signature QR code. The hot
wallet scans that and broadcasts. No bytes traverse any network
interface on the signing device.

### What if I accidentally enable WiFi?

Zigner detects connectivity changes and warns you. But the fundamental
guarantee is gone: any malware on the device could have exfiltrated keys
during the window the radio was active. Treat it as a compromise.

## Zcash

### What can I sign?

- Orchard shielded actions (RedPallas on Pallas)
- Transparent inputs (secp256k1 ECDSA, P2PKH)
- PCZT (Partially Created Zcash Transactions) for multi-party flows
- FROST-coordinated threshold spends (see [FROST multisig](#frost-multisig))

### How does Zafu/Zashi pairing work?

1. Export your Unified Full Viewing Key (UFVK) from Zigner as a QR code
   (ZIP-316).
2. Import into your hot wallet (Zafu, Zashi) as a watch-only account.
3. The hot wallet syncs notes against the chain and exports them to
   Zigner as a `ur:zcash-notes` bundle (see [anchor attestation](#anchor-attestation)).
4. The hot wallet constructs a PCZT for any spend and shows it as
   animated QR codes.
5. Zigner inspects the PCZT (anchor match, known spends, value
   consistency), shows recipient + amount + fee, and signs on approval.
6. Zigner returns the signed PCZT as QR; the hot wallet broadcasts.

### What does Zigner check before signing a PCZT?

- The PCZT's anchor matches the verified anchor stored on the device.
- Every spend nullifier matches a verified note (no unknown spends).
- Implied spend value is consistent with the verified balance.
- If the device has held FROST keys at any point, the note bundle must
  carry a valid attestation signature.

If any check fails, signing is refused with a specific error. There is
no override — these invariants block every Zcash signing path.

### What key derivation is used?

- Orchard: ZIP-32 at `m/32'/133'/account'`
- Transparent: BIP-44 at `m/44'/133'/account'/change/index`
- Unified addresses and UFVKs per ZIP-316

### Mainnet and testnet?

Both supported. Network detection is built into the signing flow.

### Why does the recipient address have a "tap to reveal" hint?

The PCZT review screen shows recipients in middle-truncated form
(`u1abc…wxyz`) for layout, but tapping reveals the full address in
4-char-chunked monospace. **Tap and read it before approving** — the
truncation hides exactly the bytes a malicious host would substitute.

## FROST multisig

### What is FROST?

A threshold signature scheme: a group of *n* participants collectively
hold a single Orchard spending key, and any *t* of them can produce a
valid signature without ever reconstructing the key. Zigner uses
[`frost-spend`](https://github.com/rotkonetworks/zcli/tree/master/crates/frost-spend),
a RedPallas FROST implementation built on the audited ZF FROST crates.

### How is the multisig set up?

Distributed Key Generation (DKG) runs in three rounds, all over animated
QR codes:

1. Each participant generates an ephemeral commitment, broadcasts it.
2. Each participant verifies all peer broadcasts, generates per-peer
   shares, broadcasts them.
3. Each participant aggregates the shares into a final key package.

No single participant ever sees the group spending key. Zigner stores
its key package in encrypted sled storage; the ephemeral DKG seed is
zeroed after round 3.

### How is signing coordinated?

Round 1 produces a nonce + signing commitment per signer. Once *t*
commitments are exchanged, each signer produces a share in round 2.
The coordinator aggregates the shares into a final RedPallas signature.

Each per-action randomizer α is bound to the sighash; nonce reuse is
hard-rejected by a SHA-256 fingerprint tracker — reusing a FROST nonce
with different messages would leak the spending key.

### Is there a relay server?

No. DKG and signing both run end-to-end over QR codes between Zigner
and Zafu (or any compatible coordinator). The group's QR cadence is
matched between Zigner and Zafu so handoffs are reliable.

### Can FROST shares be backed up?

Yes — see [Encrypted backup](#encrypted-backup).

## Anchor attestation

### What is it?

A signature over the Zcash anchor (Orchard root) plus block height and
network flag, produced by a pinned ed25519 verifier (in production, a
key controlled by Rotko Networks). The signer trusts this attestation
to assert that the anchor it's about to sign against actually exists
on the chain.

The attestation digest is domain-separated:
`SHA-256("zcash-anchor-v1" || verifier_pubkey || anchor || height || mainnet)`.

### Why?

Without it, a compromised hot wallet on a fresh single-signer device
could fabricate an arbitrary note tree and persuade the signer to
authorize spends against fake notes. Once a device has participated
in any FROST DKG, a sticky flag is set in the database and
attestation becomes mandatory permanently — even if all FROST wallets
are later deleted.

### What if attestation fails?

Signing is refused. The error states clearly that the bundle has no
valid attestation; the user must fetch a properly attested anchor from
their indexer (zidecar in the Rotko stack).

## ZID auth

### What is it?

A site-scoped ed25519 identity, derived per-origin from the master seed.
Used for OAuth-less authentication on web wallets, Zafu pro, and any
service that supports the ZID challenge protocol.

### How does cross-site correlation get prevented?

Each origin gets a domain-separated key:
`HMAC-SHA512(zid_root, "site:{origin}")`. Two sites never see the same
public key for the same user.

### Can I sign a stale challenge?

No. The Rust layer rejects challenges older than 5 minutes or more than
60 seconds in the future, regardless of what the UI shows. Replay
defense is enforced at the signing path, not just the screen.

## Hot wallet (Zafu pro)

### What is it?

A 12-word BIP39 mnemonic deterministically derived from the master
seed, exported as `ur:zafu-hot-wallet` QR for use in Zafu pro. Same
flow as a regular hot wallet pairing but with a separate spending
seed for daily-use convenience.

### Is it isolated from the master seed?

It shares the seed family. The derivation is one-way (HMAC-SHA512), so
compromising the hot wallet does not let an attacker reverse the master.
But the hot wallet is **not** a security boundary — it's a usability
shortcut. If the hot wallet device is compromised, treat both wallets
as compromised and rotate.

### Can I rotate the hot wallet?

Not yet — see [issue #11](https://github.com/rotkonetworks/zigner/issues)
for the rotation-counter proposal.

## Encrypted backup

### What's in a backup?

- All saved key sets (encrypted seeds + metadata)
- FROST key packages and group metadata (per multisig name)
- Contacts (address book)
- Wallet labels and rename history
- The sticky attestation-required flag

The seed phrase itself is **not** in the backup — the seed phrase is
the decryption key. You need both for full restore.

### What's the encryption?

XChaCha20-Poly1305. The 32-byte key is `HMAC-SHA512("zigner-backup",
seed_phrase)[:32]`. The format version (currently v2) is bound into
the AEAD's associated data, so a v2 ciphertext cannot be presented
as a forged v1 (or future v3) by stripping the version byte.

### Can I restore on a different device?

Yes. Install Zigner, enter the seed phrase, and scan the backup QR.
All saved metadata (FROST shares, contacts, labels) restores in one
operation. The attestation-required flag also restores so the device
preserves its security posture.

## Penumbra

### What can I sign?

All transaction actions: spends, outputs, swaps, liquidity positions,
delegate/undelegate/claim, delegator votes, Dutch auctions, ICS20
withdrawals.

### How does Prax pairing work?

1. Export your Full Viewing Key (FVK) from Zigner as a QR code (UR).
2. Import into Prax as watch-only.
3. Prax constructs transactions and shows QR codes.
4. Scan with Zigner, review, approve.
5. Scan the signature QR back into Prax to broadcast.

### Is the chain ID validated?

Yes. Every signing request includes a chain ID. Zigner rejects requests
where the chain ID doesn't match what the transaction plan specifies.
Prevents cross-chain replay and mainnet/testnet confusion.

## Substrate

Polkadot, Kusama, and Westend ship built-in. Sr25519 and Ed25519
signing. Substrate is a secondary use case for Zigner; if you need
chain-agility tooling, use a dedicated Polkadot signer.

## Seeds and keys

### Can I use one seed for Zcash, Penumbra, and Substrate?

Yes. Each chain derives keys from the same BIP-39 seed using distinct
derivation paths (different BIP-44 coin types), so keys are
cryptographically isolated per chain.

### What is a derived key?

A key produced by applying a derivation path to a seed. Recovery
requires only the seed phrase and the path, not the derived key
itself.

### Can I rename a seed?

No. Seed names are bound at creation time as a security invariant. To
change a name: back up the seed phrase, remove the key set, re-add it
with the new name. (FROST multisig wallets *can* be renamed — that's
a different code path.)
