# FAQ

- [About](#about)
- [Penumbra](#penumbra)
- [Zcash](#zcash)
- [Substrate Networks](#substrate-networks)
- [Seeds and keys](#seeds-and-keys)

## About

### What is Zigner?

Zigner is an air-gapped cold wallet app that turns an offline smartphone into a secure hardware wallet. It supports Penumbra, Zcash, and Substrate-based chains (Polkadot, Kusama). Your private keys never leave the device — all communication happens via QR codes.

### Should I use Zigner?

Zigner is optimized for the highest security requirements for privacy-focused blockchains. If you hold Penumbra or Zcash assets and want hardware-wallet-grade security without trusting a hardware vendor, Zigner is for you. Get in touch via [GitHub Issues](https://github.com/rotkonetworks/zigner/issues) if you need help.

### How does an offline device communicate with the outside world?

Communication happens through scanning and generating QR codes. Your hot wallet (Prax, Zafu, Zashi, Polkadot.js) constructs a transaction and encodes it as a QR code. Zigner scans it, signs it offline with your private key, and displays a signature QR code that your hot wallet scans to broadcast the transaction. Keys never leave the air-gapped device.

### How do I keep my keys secure?

Zigner keeps your keys safe on an air-gapped device, but you must also back up your seed phrases. We recommend paper backups stored in safe locations. Zigner also supports [Banana Split](https://bs.parity.io/) — Shamir Secret Sharing that splits your seed into QR code shards requiring a threshold to reconstruct.

## Penumbra

### What Penumbra operations can I sign?

Zigner supports signing all major Penumbra transaction actions:
- **Shielded transfers** — spends and outputs
- **DEX** — swaps, liquidity position open/close/withdraw
- **Staking** — delegate, undelegate, undelegate claim
- **Governance** — delegator votes
- **Dutch auctions** — schedule, end, withdraw
- **IBC** — ICS20 withdrawal for cross-chain transfers

### How do I use Zigner with Prax?

1. In Zigner, export your Penumbra Full Viewing Key (FVK) as a QR code
2. Import the FVK into Prax to create a watch-only wallet
3. Construct transactions in Prax — it will display a QR code
4. Scan the transaction QR with Zigner, review and approve
5. Zigner displays a signature QR — scan it with Prax to broadcast

### Does Zigner validate the Penumbra chain ID?

Yes. Zigner validates the chain ID in every transaction plan to prevent cross-chain signing attacks.

## Zcash

### What Zcash operations can I sign?

- **Orchard (shielded)** — RedPallas signatures on the Pallas curve
- **Transparent** — secp256k1 ECDSA signatures for legacy P2PKH inputs
- **PCZT** — Partially Constructed Zcash Transactions for multi-party signing workflows

### How do I use Zigner with Zafu or Zashi?

1. In Zigner, export your Unified Full Viewing Key (UFVK) as a QR code
2. Import the UFVK into your hot wallet (Zafu or Zashi) to create a watch-only wallet
3. Construct transactions in your hot wallet — it will display a QR code (UR-encoded)
4. Scan the transaction QR with Zigner, review and approve
5. Zigner displays a signature QR — scan it with your hot wallet to broadcast

### Does Zigner support both mainnet and testnet?

Yes. Zigner supports Zcash mainnet and testnet, with network detection built into the signing flow.

### What key derivation does Zigner use for Zcash?

- Orchard keys: ZIP-32 derivation at `m/32'/133'/account'`
- Transparent keys: BIP-44 derivation at `m/44'/133'/account'/change/index`
- Unified addresses and UFVKs per ZIP-316

## Substrate Networks

### What Substrate networks does Zigner support?

Out of the box: Polkadot, Kusama, and Westend. Any Substrate-based network can be added by scanning network specs and metadata QR codes.

### How can I update network metadata?

Scan multipart metadata QR codes from [metadata.parity.io](https://metadata.parity.io/) or [metadata.rotko.net](https://metadata.rotko.net) for parachains.

### How can I add a new network?

Follow the [Add New Network](../tutorials/Add-New-Network.md) guide.

## Seeds and keys

### Can I use the same seed for Penumbra, Zcash, and Substrate?

Yes. Zigner derives keys for each chain from the same seed phrase using chain-specific derivation paths (BIP-44 coin types), so keys are isolated per chain while sharing a single backup.

### What is the difference between seed key and derived key?

A seed key is generated directly from a seed phrase. Derived keys are "grown" from a seed by adding derivation paths. The main advantage: derived keys only need a derivation path backed up (alongside the seed phrase) for recovery.

### How can I rename a seed?

Due to security considerations, you cannot rename a seed. Back up the seed and derived keys, remove it, and add the seed again with a new name.
