<div align="center">

# Zigner

Air-gapped cold signer for Penumbra, Zcash, and Substrate chains

Part of the [Zafu](https://github.com/rotkonetworks/zafu) ecosystem

</div>

## Threat model

Zigner assumes the signing device is never connected to any network after
initial setup. All key material is generated and stored on-device. Transaction
payloads arrive as QR codes, get parsed and displayed for review, then signed
and returned as QR codes. The only output channel is the screen.

The device MUST have WiFi, Bluetooth, NFC, and cellular disabled. Airplane
mode is the minimum. Physically removing wireless hardware is better.

On devices with a secure element (Pixel 8+ Titan M2, Samsung Knox), seed
encryption keys are generated and stored inside the hardware module via
Android StrongBox. The key never exists in main memory. On iOS, seeds are
Keychain-backed by the Secure Enclave. Zigner reports the detected security
level in Settings.

Recommended: Pixel 8+ running GrapheneOS. See
[Security and Privacy](docs/src/about/Security-And-Privacy.md) for details.

What Zigner does NOT protect against:

- A compromised build toolchain (use reproducible builds and verify checksums)
- Physical access to an unlocked device with no secure element
- A user who approves a transaction without reading it
- Side-channel attacks on the device hardware (partially mitigated by StrongBox)

## Penumbra

Signs all transaction actions: shielded spends/outputs, DEX swaps, liquidity
positions, delegate/undelegate/claim, delegator votes, Dutch auctions
(schedule/end/withdraw), ICS20 withdrawals.

Chain ID is validated on every signing request to prevent cross-chain replay.

Full Viewing Key export (bech32m, UR) for import into [Prax](https://praxwallet.com).

## Zcash

- Orchard: RedPallas signatures over shielded actions
- Transparent: secp256k1 ECDSA for t-address inputs
- PCZT: Partially Created Zcash Transactions for multi-party signing
- Key derivation: ZIP-32 (`m/32'/133'/account'`), BIP-44 transparent
- UFVK export per ZIP-316 for Zashi/Zafu import

UR-encoded animated QR codes (Keystone wire format). Mainnet and testnet.

## Substrate

Polkadot, Kusama, Westend built-in. Any Substrate chain addable via QR
metadata updates. Sr25519 and Ed25519 signing.

## Hot wallet pairing

| Chain | Hot wallet | Wire format |
|-------|-----------|-------------|
| Penumbra | [Prax](https://praxwallet.com) | UR / CBOR |
| Zcash | [Zafu](https://github.com/rotkonetworks/zafu), Zashi | UR / PCZT / ZIP-316 |
| Substrate | Polkadot.js | UOS |

The hot wallet holds only viewing keys. It constructs unsigned transactions,
encodes them as QR, and scans back the signed response.

## Architecture

Native iOS (Swift) and Android (Kotlin/Compose) over a shared Rust core. All
cryptography, key derivation, transaction parsing, and signing lives in Rust.
The native layers handle UI, camera, and QR rendering.

```
rust/
  transaction_signing/   Penumbra, Zcash, Substrate signers
  transaction_parsing/   QR payload decoder
  db_handling/           Key storage, metadata, seeds
  navigator/             Screen state machine
  signer/                UniFFI bridge to native
  qrcode_rtx/            Animated QR encoder (fountain codes)
  qr_reader_phone/       Camera frame QR decoder
  generate_message/      Airgap metadata update generator
  zcash-wasm/            Zcash Orchard derivation for browser wallets
ios/                     Swift + SwiftUI
android/                 Kotlin + Jetpack Compose
```

## Building

Requires [Rust](https://www.rust-lang.org/tools/install) and uniffi-bindgen
matching the project version:

```
cargo install uniffi_bindgen --version 0.22.0
```

[opencv crate dependencies](https://crates.io/crates/opencv) must be present.

### Android

```
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

Install [Android Studio](https://developer.android.com/studio) with NDK
`24.0.8215888`. Open the project root and build.

### iOS

Open `ios/PolkadotVault.xcodeproj` in Xcode. Build and run.

## Releasing (Android)

1. Bump `versionName` in `android/build.gradle`
2. Merge to master
3. Tag `v*` (e.g. `v0.2.0`)

`android-release.yml` runs: test, build in pinned container, sign (v2+v3+v4),
checksum (SHA-256/SHA-512), SLSA provenance attestation, publish to GitHub
Releases. Tags containing `-` (e.g. `v1.0.0-rc1`) publish as pre-releases.

## Tests

```
cd rust && cargo test --locked
```

## License

[GPL-3.0](LICENSE)
