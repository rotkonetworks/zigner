<div align="center">

![Logo Black](docs/src/res/logo-black.svg#gh-light-mode-only)
![Logo White](docs/src/res/logo-white.svg#gh-dark-mode-only)

</div>

<div align="center">
    <br><br>
    Air-gapped cold storage for Zcash, Penumbra, and other privacy-focused chains
    <br><br>
</div>

# Introduction

Zigner Zafu is a mobile cold wallet application that allows any smartphone to act as an air-gapped crypto wallet for Zcash and Penumbra. This is also known as "cold storage".

Zigner Zafu supports:
- **Zcash**: Orchard shielded pool with ZIP-32 key derivation
- **Penumbra**: Privacy-preserving transfers with decaf377 signatures
- **Polkadot ecosystem**: Substrate-based networks (legacy support)

You can create wallets, sign transactions, and manage your private keys without any network connectivity enabled on the device.

☝️ **Disabling the mobile phone's networking abilities is a requirement for the app to be used as intended**

All data transfer to and from the app happens using QR codes. By doing so, the most sensitive piece of information—your private keys—will never leave the phone.

**Available for both iOS and Android.**

![](docs/src/res/screens-for-readme.png)

# Features

- Generate and store private keys with BIP39 seed phrases
- Sign Zcash Orchard shielded transactions
- Sign Penumbra privacy-preserving transfers
- Export Full Viewing Keys (FVKs) for Zcash and Penumbra watch-only wallets
- Parse and sign transactions via QR codes
- Use derived keys for multiple addresses with a single seed phrase
- Backup and restore your seed phrases
- View activity log to detect unauthorized access
- Air-gapped operation - no network connectivity required

# Key Differences from Polkadot Vault

Zigner Zafu is a fork of [Polkadot Vault (formerly Parity Signer)](https://github.com/novasamatech/parity-signer) adapted for Zcash and Penumbra:

- **Zcash Support**: Full support for Orchard shielded transactions using ZIP-32 key derivation
- **Penumbra Support**: Native support for Penumbra's decaf377-rdsa signatures
- **FVK Export**: Export Full Viewing Keys for watch-only wallet integration with Zafu and other viewers
- **QR-based Signing**: Sign complex shielded transactions via animated QR codes
- **Privacy Focus**: Designed specifically for privacy-preserving cryptocurrency networks

# Project Structure

Zigner is a native app for iOS and Android. Native UIs are written in Swift and Kotlin and built on top of a universal Rust core library, which implements all the cryptographic logic.

- `android` - Android project. Builds by Android Studio automatically
- `docs` - Documentation
- `ios` - iOS project folder
- `rust` - Backend Rust code containing all cryptographic operations and signing logic
- `scripts` - Build and release scripts

The Rust folder contains the core signing logic:

- `db_handling` — Database operations and key management for Zcash, Penumbra, and Substrate chains
- `definitions` — Core types and data structures
- `signer` — FFI interface to bridge native code with Rust backend
- `transaction_parsing` — QR payload parsing for all supported chains
- `transaction_signing` — Signing operations for Zcash, Penumbra, and Substrate

# Build Process

**1.** Install the latest [Rust](https://www.rust-lang.org/tools/install).

**2.** Install `uniffi-bindgen` (version must match project, currently `0.22.0`):

   ```bash
   cargo install uniffi_bindgen --version 0.22.0
   ```

**3.** Ensure [opencv crate dependencies](https://crates.io/crates/opencv).

## iOS

**4.** Install [Xcode](https://developer.apple.com/xcode/).

**5.** Open the `PolkadotVault.xcodeproj` project from the `ios` folder.

**6.** Select a scheme and click Run (Cmd+R):
- `PolkadotVault` - Production scheme
- `PolkadotVault-Dev` - Development scheme with offline mode simulation
- `PolkadotVault-QA` - TestFlight QA builds

**Note:** Use a real device for development, as camera functionality is essential and may not work in the simulator.

## Android

**4.** Install necessary rust targets:

   ```bash
    rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   ```

**5.** Download [Android Studio](https://developer.android.com/studio).

**6.** Open the project from the root directory.

**7.** Install NDK version 24.0.8215888 (SDK Manager → SDK Tools → enable "Show package details").

**8.** Connect device or create virtual device (Tools → Device Manager).

**9. (macOS):** Specify python path in `local.properties`:

```
rust.pythonCommand=python3
```

**10.** Run the project (Ctrl+R). It will build the Rust core automatically.

# Tests

Core Rust code is fully covered by tests:

```
cd rust && cargo test --locked
```

# Supported Networks

## Zcash
- Orchard shielded pool support
- ZIP-32 key derivation (m/32'/133'/account')
- Unified addresses
- Full Viewing Key (FVK) export for watch-only wallets

## Penumbra
- Decaf377-rdsa signatures
- BIP32-style key derivation (m/44'/6532'/account')
- Full Viewing Key (FVK) export
- Shielded transfers and staking operations

## Substrate-based (Legacy)
- Polkadot, Kusama, Westend
- Sr25519, Ed25519, ECDSA encryption support

# Integration with Zafu

Zigner works seamlessly with [Zafu](https://github.com/penumbra-zone/web) and [Prax](https://github.com/prax-wallet/prax):

1. Create or import a seed phrase in Zigner
2. Export the Full Viewing Key (FVK) via QR code
3. Scan the FVK QR code in Zafu/Prax to import as watch-only wallet
4. Use Zafu/Prax to create transactions
5. Scan transaction QR codes in Zigner to sign
6. Broadcast signed transactions from Zafu/Prax

# Bugs and Feedback

If you found a bug or want to propose an improvement, please open [an issue](https://github.com/rotkonetworks/zigner/issues).

Try to create bug reports that are:

- _Reproducible._ Include steps to reproduce the problem.
- _Specific._ Include as much detail as possible: which version, what phone, OS, etc.
- _Unique._ Do not duplicate existing opened issues.
- _Scoped to a Single Bug._ One bug per report.

# Contributing

Contributions are welcome! Please participate in discussions and send PRs. Each PR should be reviewed by at least one project maintainer.

# License

Zigner Zafu is [GPL 3.0 licensed](LICENSE).
