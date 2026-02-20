# FAQ

- [Security](#security)
- [Penumbra](#penumbra)
- [Zcash](#zcash)
- [Substrate](#substrate)
- [Seeds and keys](#seeds-and-keys)

## Security

### What is Zigner?

An air-gapped cold signer. It holds private keys on an offline phone and
signs transactions presented as QR codes. It never touches a network.

### What does it protect against?

A compromised hot wallet. Even if Prax, Zafu, or Polkadot.js is backdoored,
the attacker cannot extract your spending key because it never leaves the
signing device. They can present a malicious transaction, but Zigner displays
the decoded contents for you to review before signing.

### What does it NOT protect against?

- You approving a transaction you didn't read
- Physical access to the unlocked device
- A supply chain attack on Zigner itself (verify reproducible builds)
- Side channels on the phone hardware (EM, power analysis)

### How does the device communicate?

QR codes only. The hot wallet encodes an unsigned transaction as a QR code.
Zigner scans it, displays the parsed contents, signs if approved, and shows
a signature QR code. The hot wallet scans that and broadcasts. No bytes
traverse any network interface on the signing device.

### What if I accidentally enable WiFi?

Zigner detects connectivity changes and warns you. But the fundamental
guarantee is gone: any malware on the device could have exfiltrated keys
during the window the radio was active. Treat it as a compromise.

## Penumbra

### What can I sign?

All transaction actions: spends, outputs, swaps, liquidity positions,
delegate/undelegate/claim, delegator votes, Dutch auctions, ICS20
withdrawals.

### How does Prax pairing work?

1. Export your Full Viewing Key (FVK) from Zigner as a QR code
2. Import into Prax (watch-only)
3. Prax constructs transactions and shows QR codes
4. Scan with Zigner, review, approve
5. Scan the signature QR back into Prax to broadcast

### Is the chain ID validated?

Yes. Every signing request includes a chain ID. Zigner rejects requests
where the chain ID doesn't match what the transaction plan specifies. This
prevents cross-chain replay and mainnet/testnet confusion.

## Zcash

### What can I sign?

- Orchard shielded actions (RedPallas on Pallas)
- Transparent inputs (secp256k1 ECDSA, P2PKH)
- PCZT (Partially Created Zcash Transactions) for multi-party flows

### How does Zafu/Zashi pairing work?

Same flow as Penumbra: export a Unified Full Viewing Key (UFVK) per ZIP-316,
import into your hot wallet as watch-only, then scan transaction QRs back
and forth. Wire format is UR-encoded (Keystone SDK compatible).

### What key derivation is used?

- Orchard: ZIP-32 at `m/32'/133'/account'`
- Transparent: BIP-44 at `m/44'/133'/account'/change/index`
- Unified addresses and UFVKs per ZIP-316

### Mainnet and testnet?

Both supported. Network detection is built into the signing flow.

## Substrate

### What networks are supported?

Polkadot, Kusama, and Westend ship built-in. Any Substrate chain can be
added by scanning its network specs and metadata as QR codes from
[metadata.parity.io](https://metadata.parity.io/) or
[metadata.rotko.net](https://metadata.rotko.net).

### How do I update metadata?

Scan the multipart metadata QR from the portal for your network. Zigner
validates the metadata signature against the verifier certificate before
accepting it.

## Seeds and keys

### Can I use one seed for Penumbra, Zcash, and Substrate?

Yes. Each chain derives keys from the same BIP-39 seed using distinct
derivation paths (different BIP-44 coin types), so keys are cryptographically
isolated per chain.

### What is a derived key?

A key produced by applying a derivation path to a seed. Recovery requires
only the seed phrase and the path, not the derived key itself.

### Can I rename a seed?

No. Seed names are bound at creation time as a security invariant. To change
a name: back up the seed phrase, remove the key set, re-add it with the new
name.

### What is Banana Split?

Shamir Secret Sharing for seed phrases. Splits a seed into N QR code shards
with a threshold of K required to reconstruct. No single shard reveals
anything about the seed. Uses [bs.parity.io](https://bs.parity.io/) for
shard encoding.
