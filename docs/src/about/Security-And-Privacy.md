# Security and Privacy

## Recommended device

The strongest configuration is a **Pixel 8 or later running GrapheneOS**.

Why:

- **Titan M2 secure element.** Zigner stores seed encryption keys in
  StrongBox (the Titan M2). Key material never exists in main memory in
  plaintext. Even with physical access and a JTAG probe, an attacker
  cannot extract keys from the secure element without defeating its
  tamper mesh.

- **Verified boot with a locked bootloader.** GrapheneOS uses its own
  signing keys. Zigner's device attestation treats both OEM-signed and
  self-signed verified boot as secure (bootloader locked either way).
  An unlocked bootloader is flagged as insecure because it allows
  booting a modified OS that could extract keys.

- **No known remote exploit chain.** Leaked NSO Group capability
  documents from 2023 showed Pegasus had no working exploit chain
  against GrapheneOS on Pixel 6+ hardware. The Titan M2 (Pixel 8+) adds
  a stronger secure element on top of that.

- **Hardened memory allocator, per-profile encryption, reduced attack
  surface.** GrapheneOS strips Google Play Services, tightens SELinux
  policy, and applies memory safety hardening that stock Android does
  not.

If you cannot get a Pixel, any device with StrongBox or a TEE (Trusted
Execution Environment) provides hardware-backed key storage. Zigner
detects what's available and reports it in Settings. Software-only key
storage is explicitly flagged as insecure.

## Device setup

1. Factory reset the device.
2. Install GrapheneOS (or your OS of choice).
3. Enable full-disk encryption with a strong passphrase. Do not rely
   solely on biometrics for device unlock — fingerprints and face
   scans can be compelled.
4. Install Zigner from [GitHub Releases](https://github.com/rotkonetworks/zigner/releases).
   Verify the APK against `SHA256SUMS` and the ssh signature on
   `SHA256SUMS.sig` using the project's release public key.
5. Enable airplane mode. Disable WiFi, Bluetooth, NFC, and cellular.
   Physically removing wireless hardware is better if the device
   allows it.
6. Never connect the device to a computer. Only charge on a dedicated
   power adapter from the manufacturer.

## What Zigner binds to hardware

On Android with StrongBox (Pixel 8+ Titan M2, Samsung Knox, etc.):

- Seed encryption key is AES-256-GCM generated inside the secure
  element via `setIsStrongBoxBacked(true)`. The key never leaves the
  element.
- Key is invalidated if biometric enrollment changes (new fingerprint
  added).
- Key requires the device to be unlocked and the user to authenticate
  within 30 seconds.
- Device attestation checks the bootloader state, OS version, and
  security patch level before signing.

On iOS:

- Seeds are stored in the Keychain with
  `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, backed by the
  Secure Enclave. The Keychain item is bound to the device and
  requires the device passcode.

## Cryptographic invariants enforced at the Rust layer

Zigner does not blindly sign anything. Independent of the UI, every
Zcash signing path enforces the following at the Rust core:

- **Anchor binding** — the PCZT's anchor must equal the verified
  anchor stored on the device. Mismatched anchors are refused.
- **Known-spend cross-reference** — every spend nullifier in the PCZT
  must correspond to a verified note. Bundles with unknown spends are
  refused.
- **Value consistency** — implied spend value must be ≤ the verified
  balance. Bundles that overspend are refused.
- **FROST nonce reuse defense** — a SHA-256 fingerprint of every used
  nonce is held in memory; reuse is hard-rejected with a CRITICAL
  error.

For FROST multisig devices:

- **Sticky attestation** — once a device has held FROST keys, every
  subsequent note import must carry a valid attestation signed by the
  pinned ed25519 verifier key. The flag survives FROST wallet
  deletion, defending against a downgrade where an attacker deletes
  the multisig and tries to feed fabricated notes through a fresh
  single-signer mode.
- **Strict attestation length** — only 64-byte ed25519 attestations
  are accepted; a 96-byte FROST attestation cannot fall through this
  path with its randomizer silently dropped.

For ZID auth:

- **Challenge freshness** — the Rust layer rejects any auth challenge
  older than 5 minutes or more than 60 seconds in the future,
  regardless of what the UI shows.
- **Domain separation** — site-specific keys derive from
  `HMAC-SHA512(zid_root, "site:{origin}")`, so two sites can never
  request signatures with the same public key.

For backups:

- **Authenticated AEAD** — backup ciphertexts use XChaCha20-Poly1305
  with the format version bound into the associated data. A v2
  backup cannot be presented as a forged v1 (or future v3) by
  stripping the version byte; the auth tag won't validate.

See the multi-reviewer security pass in
[v0.4.1 changelog](./Changelog.md) for details.

## Updating Zigner

Your device should never go online. To update:

1. Verify you have the recovery phrase for every key set, **and** an
   encrypted backup if you have FROST groups, contacts, or labels you
   want to preserve.
2. Factory reset the device.
3. Reinstall OS and Zigner, verify APK checksum and ssh signature.
4. Re-enable airplane mode and disable all radios.
5. Recover your accounts from the seed phrases. If you have a backup,
   restore it after entering the seed phrase to bring back FROST
   shares, contacts, and labels.

## Data collection

None. Zigner makes zero network requests and collects no telemetry.
