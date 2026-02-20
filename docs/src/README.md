# Zigner

Air-gapped cold signer for Penumbra, Zcash, and Substrate chains. Private
keys never leave the device. All communication is QR codes.

The device MUST remain offline at all times. See
[Security and Privacy](./about/Security-And-Privacy.md).

## Supported chains

- Penumbra: shielded signing, FVK export (Prax compatible)
- Zcash: Orchard + transparent signing, PCZT, UFVK export (Zashi/Zafu)
- Substrate: Polkadot, Kusama, Westend, any chain via metadata QR updates

## Guides

- [Getting started](./tutorials/Start.md)
- [Upgrading](./tutorials/Upgrading.md)
- [Add new network](./tutorials/Add-New-Network.md) (Substrate)
- [Kusama tutorial](./tutorials/Kusama-tutorial.md)
- [Key derivation](./tutorials/Hierarchical-Deterministic-Key-Derivation.md)
- [FAQ](./about/FAQ.md)

## License

[GPL-3.0](LICENSE)
