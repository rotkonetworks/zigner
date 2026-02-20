# Zigner — Privacy-first air-gapped cold wallet

Zigner turns any smartphone into a hardware wallet for privacy-focused blockchains. Your private keys never leave the device — all communication happens via QR codes.

## Supported chains

- **Penumbra** — shielded spends, outputs, DEX swaps, staking, governance, IBC withdrawals, FVK export (Prax compatible)
- **Zcash** — Orchard shielded signing, transparent signing, PCZT support, UFVK export (Zashi/Zafu compatible)
- **Substrate** — Polkadot, Kusama, Westend, and any Substrate chain via metadata QR updates

All data transfer uses QR codes. The device must remain offline (airplane mode minimum) at all times.

**Disabling the mobile phone's networking abilities is a requirement for the app to be used as intended, check our [Security and Privacy](./about/Security-And-Privacy.md) page for more details.**

## Key features

- **Cold signing** for Penumbra, Zcash, and Substrate transactions
- **Full Viewing Key export** for watch-only wallet import (Prax, Zashi, Zafu)
- **PCZT support** for multi-party Zcash transaction signing
- **Banana Split backup** — split your seed phrase into QR code shards via Shamir Secret Sharing
- **Air-gap detection** — warns if network connectivity is detected
- **Activity log** — detect unauthorized access to your device
- **Multi-seed support** — manage multiple seed phrases and derived keys

## Getting Started

[Getting started guide](./tutorials/Start.md)

### User Guides

- [Start](./tutorials/Start.md)
- [Upgrading](./tutorials/Upgrading.md)
- [Add New Network](./tutorials/Add-New-Network.md) (Substrate)
- [Kusama tutorial](./tutorials/Kusama-tutorial.md)
- [Key Derivation](./tutorials/Hierarchical-Deterministic-Key-Derivation.md)

### About

- [FAQ](./about/FAQ.md)
- [Security and Privacy](./about/Security-And-Privacy.md)

## License

Zigner is [GPL 3.0 licensed](LICENSE).
