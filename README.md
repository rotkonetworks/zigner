<div align="center">

# Zigner

Air-gapped cold signer for Penumbra, Zcash, and Substrate chains

</div>

## Overview

Zigner is an offline signing tool for mobile devices. It holds private keys on a permanently air-gapped phone and communicates with online watch-only wallets exclusively through QR codes. No network stack is used at runtime — no WiFi, Bluetooth, NFC, or cellular. Airplane mode is the minimum requirement.

The threat model assumes the signing device is never connected to any network after initial setup. All key material is generated and stored on-device. Transaction payloads arrive as QR codes from the companion hot wallet, get parsed and displayed for user review, then signed and returned as animated QR codes. The hot wallet never sees the spending key.

## Security Properties

**Key isolation** — Spending keys never leave the device. There is no USB, Bluetooth, or network exfiltration path. The only output channel is the camera displaying QR codes.

**Transaction review** — Every transaction is decoded and displayed before signing. The user sees exactly what they are approving: destination addresses, amounts, fees, memo fields, and chain identifiers. No blind signing.

**Chain ID binding** — Penumbra transactions are bound to a specific chain ID. This prevents a malicious hot wallet from replaying a testnet signature on mainnet or across forks.

**Deterministic builds** — Android release builds run in a pinned container image with reproducible toolchains. APKs are signed with apksigner (v2+v3+v4 schemes) and ship with SHA-256/SHA-512 checksums and SLSA provenance attestations.

**Seed backup** — Banana Split (Shamir Secret Sharing) lets you split a seed phrase across multiple shares with a configurable threshold. No single share reveals the seed.

## Penumbra

Zigner signs all Penumbra transaction actions:

- Shielded spends and outputs
- DEX swaps and liquidity positions
- Staking: delegate, undelegate, claim
- Governance: delegator votes
- Dutch auctions: schedule, end, withdraw
- IBC withdrawals (ICS20)

Full Viewing Key export in bech32m and UR format for import into Prax or other watch-only wallets. Chain ID is validated on every signing request.

## Zcash

Zcash support covers both shielded and transparent pools:

- **Orchard** — RedPallas signatures over shielded spends and outputs
- **Transparent** — secp256k1 ECDSA for t-address inputs
- **PCZT** — Partially Created Zcash Transactions for multi-party and hardware signer workflows
- **Key derivation** — ZIP-32 hierarchical deterministic keys
- **UFVK export** — Unified Full Viewing Keys per ZIP-316, importable into Zashi and Zafu

UR-encoded animated QR codes (Keystone SDK wire format). Mainnet and testnet.

## Substrate

- Polkadot, Kusama, Westend built-in
- Any Substrate chain addable via QR metadata updates
- BIP32-Ed25519 derivation (Ledger-compatible paths)
- Sr25519 and Ed25519 signing

## Hot Wallet Pairing

| Chain | Hot Wallet | Wire Format |
|-------|-----------|-------------|
| Penumbra | Prax | UR / CBOR |
| Zcash | Zafu, Zashi | UR / PCZT / ZIP-316 |
| Substrate | Polkadot.js | UOS |

The hot wallet holds only viewing keys. It constructs unsigned transactions, encodes them as QR, and reads back the signed QR response from Zigner.

## Architecture

Native iOS (Swift) and Android (Kotlin/Compose) UIs on top of a shared Rust core. All cryptography, key management, transaction parsing, and signing logic lives in Rust. The native layers handle UI, camera, and QR rendering.

```
android/          Kotlin + Jetpack Compose
ios/              Swift + SwiftUI
rust/
  signer/         UniFFI bridge to native code
  db_handling/    Key storage, metadata, seeds
  navigator/      Screen state machine
  transaction_parsing/   QR payload decoder
  transaction_signing/   Penumbra, Zcash, Substrate signers
  zcash-wasm/     Zcash Orchard derivation for browser wallets
  generate_message/      Airgap metadata update generator
  qr_reader_phone/       Camera frame QR decoder
  qrcode_rtx/     Animated QR encoder (fountain codes)
```

## Building

Install [Rust](https://www.rust-lang.org/tools/install) and uniffi-bindgen (must match project version):

```
cargo install uniffi_bindgen --version 0.22.0
```

Ensure [opencv crate dependencies](https://crates.io/crates/opencv) are present.

### Android

```
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

Install [Android Studio](https://developer.android.com/studio) with NDK `24.0.8215888`. Open the project root and build.

### iOS

Open `ios/PolkadotVault.xcodeproj` in Xcode. Select scheme, build, run.

## Releasing (Android)

1. Bump `versionName` in `android/build.gradle`
2. Merge to master
3. Tag `v*` (e.g. `v0.2.0`)

The `android-release.yml` workflow handles the rest: test, build in pinned container, sign, verify, checksum, attest provenance, publish GitHub Release with APK.

Tags containing `-` (e.g. `v1.0.0-rc1`) publish as pre-releases.

## Tests

```
cd rust && cargo test --locked
```

## License

[GPL-3.0](LICENSE)
