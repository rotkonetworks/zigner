# Architecture

Zigner is a native iOS (Swift / SwiftUI) and Android (Kotlin / Jetpack
Compose) app over a shared Rust core. All cryptography, key
derivation, transaction parsing, signing, and database storage live
in Rust. The native layers handle UI, camera capture, and QR rendering.

```
zigner/
  rust/                  ← shared core (workspace)
  android/               ← Kotlin + Compose app
  ios/                   ← Swift + SwiftUI app
  docs/                  ← mdBook source for this site
```

## Rust workspace

| Crate                | Purpose                                                                               |
|----------------------|---------------------------------------------------------------------------------------|
| `signer`             | UniFFI bridge to native; owns auth, FROST, backup, hot wallet, anchor verify          |
| `transaction_signing`| Penumbra (decaf377-rdsa), Zcash (Orchard RedPallas + transparent secp256k1), Cosmos |
| `transaction_parsing`| Penumbra signing-request parser                                                       |
| `db_handling`        | Encrypted sled storage — seeds, FROST key packages, contacts, anchors, attestation flag; builds the shipped database (`make_cold_release`) |
| `qrcode_rtx`         | Animated UR encoder (raptorq fountain codes)                                          |
| `qrcode_static`      | Static QR generation                                                                  |
| `qr_reader_phone`    | Camera frame UR decoder (multi-part reassembly)                                       |
| `qr_reader_pc`       | Desktop dev tool (uses `opencv`; not part of mobile builds)                           |
| `zcash-wasm`         | Browser-compatible Orchard derivation (used by Zafu)                                  |
| `constants`          | Pinned verifier keys, sled tree names                                                 |
| `definitions`        | Shared error / model types crossed by FFI                                             |

External git dependencies:

- [`frost-spend`](https://github.com/rotkonetworks/zcli/tree/master/crates/frost-spend)
  — RedPallas FROST primitives shared with `zcli`.
- [`zoda-vss`](https://github.com/rotkonetworks/zcli/tree/master/crates/zoda-vss)
  — verifiable secret sharing over Reed–Solomon, used by FROST
  custody flows.

## FFI layer

UniFFI 0.22 generates the Kotlin and Swift bindings from
`rust/signer/src/signer.udl`. The build script in `rust/signer/build.rs`
runs at compile time and produces:

- `signer.kt` for Android (placed in the gradle build classpath)
- `signer.swift` for iOS (placed in the Xcode project)

FFI data types (dictionaries, enums) are defined in
`rust/definitions/src/navigation.rs` and re-exported via the
`signer` crate's `ffi_types.rs`.

## Database

Zigner stores all persistent state in a single encrypted **sled** key-value
database. Tree names are constants in `rust/constants/src/lib.rs`:

| Tree                  | Contents                                                 |
|-----------------------|----------------------------------------------------------|
| `addresses`           | Per-derivation address records keyed by address bytes    |
| `seedkeys`            | Encrypted seed phrases (under StrongBox / Keychain key)  |
| `frost_keys`          | FROST key packages and group metadata per multisig       |
| `contacts`            | Address book entries                                     |
| `zcash_notes`         | Verified Orchard notes + anchor metadata                 |
| `chainspecs`          | Network specs keys point at (Zcash, Penumbra, Cosmos)    |
| `settings`            | Danger status, schema version, attestation flag          |
| `history`             | Append-only device history log                           |

Databases from releases that still signed Substrate also hold
`metadata`, `verifiers` and `transaction` trees and `types` /
`general_verifier` settings. Nothing reads them any more.

Anchor metadata in `zcash_notes` is laid out as
`anchor(32) || height(4) || mainnet(1) || synced_at(8)`.

## QR wire formats

Zigner consumes and produces these UR types:

| UR type             | Direction        | Contents                                          |
|---------------------|------------------|---------------------------------------------------|
| `ur:zcash-pczt`     | hot → cold → hot | PCZT bundle (animated for large transactions)     |
| `ur:zcash-accounts` | cold → hot       | UFVK export (ZIP-316)                             |
| `ur:zcash-notes`    | hot → cold       | Verified Orchard notes + anchor + attestation     |
| `ur:zcash-signatures` | cold → hot     | Signed PCZT response                              |
| `ur:zigner-backup`  | cold ↔ cold      | Encrypted backup envelope                         |
| `ur:zigner-contacts`| cold ↔ cold      | Address book sync                                 |
| `ur:zafu-hot-wallet`| cold → hot       | Derived BIP-39 mnemonic for Zafu pro              |
| `ur:penumbra-accounts` | cold → hot    | Penumbra FVK for Prax                             |

## Native layers

Both native apps consume the UniFFI-generated bindings as their only
contact with the core. Screen flows live in the native layers and call
the Rust core for data and signing.

Camera capture (CameraX on Android, AVFoundation on iOS) hands raw
frames to the Rust `qr_reader_phone` crate, which decodes UR
fountain-code frames and returns the assembled CBOR / PCZT to the
core. QR rendering uses platform-native bitmap APIs over the byte
output of `qrcode_rtx` / `qrcode_static`.
