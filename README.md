<div align="center">

# Zigner

Privacy-first air-gapped cold wallet for Penumbra and Zcash

</div>

# Introduction

Zigner is a mobile application that turns any smartphone into an air-gapped hardware wallet. Your private keys never leave the device — all communication happens via QR codes.

Built for privacy-focused blockchains, Zigner provides cold signing for **Penumbra** shielded transactions, **Zcash** Orchard and transparent transactions, and **Substrate** chains (Polkadot, Kusama).

You must disable all networking (Wifi, Bluetooth, Mobile Data) before using Zigner. Airplane mode is the minimum requirement.

**Available for both iOS and Android.**

# Supported Chains

## Penumbra

- Shielded spends and outputs
- DEX operations (swaps, liquidity positions)
- Staking (delegate, undelegate, claim)
- Governance (delegator votes)
- Dutch auctions (schedule, end, withdraw)
- IBC withdrawals (ICS20)
- Full Viewing Key export (bech32m + UR format, compatible with Prax)
- Chain ID validation to prevent cross-chain attacks

## Zcash

- **Orchard (shielded)** transaction signing via RedPallas
- **Transparent** transaction signing via secp256k1 ECDSA
- PCZT (Partially Constructed Zcash Transaction) support for multi-party signing
- Unified Full Viewing Key (UFVK) export per ZIP-316 (compatible with Zashi)
- ZIP-32 key derivation
- Mainnet and testnet support
- UR-encoded animated QR codes (Keystone SDK compatible)

## Substrate

- Polkadot, Kusama, Westend (built-in)
- Any Substrate-based network via QR metadata updates
- Ledger-compatible BIP32-Ed25519 derivation

# Features

- Generate and store multiple seed phrases and derived keys
- Sign transactions while keeping private keys permanently offline
- Export Full Viewing Keys for watch-only wallet import
- Backup and restore via Banana Split (Shamir Secret Sharing)
- View activity log to detect unauthorized access
- Update network metadata without going online
- Add new networks via QR code

# Wallet Compatibility

| Chain | Hot Wallet | Protocol |
|-------|-----------|----------|
| Penumbra | Prax | UR / CBOR |
| Zcash | Zafu, Zashi | UR / PCZT / ZIP-316 |
| Substrate | Polkadot.js | UOS |

# Project Structure

Zigner is a native app for iOS and Android. Native UI's are written in Swift and Kotlin, built on top of a universal Rust core library that implements all the logic.

- `android` — Android project (Kotlin + Jetpack Compose)
- `ios` — iOS project (Swift)
- `rust` — backend Rust code (core logic, signing, key management)
- `docker` — CI container images
- `docs` — documentation
- `scripts` — build and release scripts

Key Rust crates:

- `signer` — FFI interface bridging native code and Rust backend
- `db_handling` — database operations and business logic
- `navigator` — unified navigation across platforms
- `transaction_parsing` — QR payload parser
- `transaction_signing` — signing logic for Penumbra, Zcash, and Substrate
- `zcash-wasm` — Zcash Orchard key derivation for browser wallets
- `generate_message` — over-the-airgap update generator

# Build Process

**1.** Install the latest [Rust](https://www.rust-lang.org/tools/install).

**2.** Install `uniffi-bindgen` (must match the project version):

```bash
cargo install uniffi_bindgen --version 0.22.0
```

**3.** Ensure [opencv crate dependencies](https://crates.io/crates/opencv).

## Android

**4.** Install Rust targets:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

**5.** Install [Android Studio](https://developer.android.com/studio) with NDK version `24.0.8215888`.

**6.** Open the project from the root directory and run (`Ctrl+R`).

## iOS

**4.** Open `ios/PolkadotVault.xcodeproj` in Xcode. Select a scheme and run (`Cmd+R`).

# Release Android

1. Update `versionName` in `android/build.gradle`
2. Merge to master
3. Tag with `v*` (e.g. `v0.2.0`)
4. The `android-release.yml` workflow automatically:
   - Runs tests
   - Builds release APK in pinned container
   - Signs with apksigner (v2 + v3 + v4 schemes)
   - Verifies signatures
   - Generates SHA-256 / SHA-512 checksums
   - Creates SLSA build provenance attestation
   - Publishes GitHub Release with APK + checksums

Tags with `-` suffix (e.g. `v1.0.0-rc1`) are published as pre-releases.

# Tests

```bash
cd rust && cargo test --locked
```

# Bugs and Feedback

[Open an issue](https://github.com/rotkonetworks/zigner/issues).

# License

Zigner is [GPL 3.0 licensed](LICENSE).
