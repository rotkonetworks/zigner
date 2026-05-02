# Zigner ecosystem

## Zigner repo

- [Zigner app](https://github.com/rotkonetworks/zigner) — air-gapped
  cold signer for Zcash, Penumbra, and Substrate
- [`generate_message` tool](https://github.com/rotkonetworks/zigner/tree/master/rust/generate_message)
  — active-side helper for over-the-airgap Substrate metadata updates
- [`qr_reader_pc`](https://github.com/rotkonetworks/zigner/tree/master/rust/qr_reader_pc)
  — desktop QR scanner used during development

## Companion projects

- [Zafu](https://github.com/rotkonetworks/zafu) — privacy-centric
  Zcash browser wallet (Chrome extension); pairs with Zigner for
  cold signing, FROST multisig, and ZID auth
- [zcli](https://github.com/rotkonetworks/zcli) — Zcash light-client
  CLI + zidecar trustless light server; source of `frost-spend` and
  `zoda-vss`
- [Zashi](https://electriccoin.co/zashi/) — Zcash mobile wallet (ECC);
  imports Zigner UFVKs and signs PCZTs through the cold-signing flow

## Compatible web wallets and tools

- [Prax](https://prax.fyi/) — Penumbra browser wallet (FVK import,
  transaction signing)
- [Polkadot.js Apps](https://polkadot.js.org/apps/) — Substrate
  transaction construction and broadcast
- [metadata.parity.io](https://metadata.parity.io/) — Substrate
  metadata QR portal
- [metadata.rotko.net](https://metadata.rotko.net) — Rotko-operated
  Substrate metadata mirror
