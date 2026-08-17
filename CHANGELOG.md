# Changelog

All notable changes to zigner are documented in this file.

## 0.11.0 - 2026-08-17

Minor, not patch. The FROST DKG wire format changed and three key
modules left the shipped binary, so this is not a drop-in patch for
0.10.0. Adds backup-to-a-public-key as an alternative to passphrase
backups, and hardens the module update lifecycle.

### Features

- age-encrypted share backup, to one or more public keys: an
  alternative to passphrase-encrypted backups, where forgetting the
  passphrase is a common way a backup turns out to be worthless -
  discovered at restore time. Recipients are ordinary `ssh-ed25519`
  lines or native `age1` recipients; this device's own recipient is
  always included in an export, derived under a dedicated backup
  domain rather than reusing the signing key. Both transports share
  one plaintext format, so the threshold cross-check on import cannot
  be skipped by arriving over the new one.
- Export/restore screens for the above, with the recipient list shown
  before export ("who can restore this" is the only question on that
  screen a user can get wrong), and restore dispatching on the age
  armor header so the user need not remember which way they backed up.

### Fixes

- FROST DKG round 2 is now sealed (frost-spend bd9c63e). Round-2
  packages were shipped in the clear on a QR, which for any n > t lets
  an observer interpolate the dealers' polynomials and recover the
  group signing key. The wire format change is version-gated and fails
  loudly on mismatch - every participant must be on 0.11.0 or later.
  Wallets from earlier ceremonies are NOT retroactively protected;
  where a ceremony could have been observed, the remedy is a fresh DKG
  and moving funds.
- Activation installs what was confirmed: staging recorded only which
  slot it wrote, so activation re-verified the slot without proving
  the bytes were the same package the user was shown. The staged
  version and module hash are now recorded and re-checked at
  activation.
- Module update state is written atomically (write-then-rename). A
  torn write left unparseable JSON, dropping `lastInstalled` to the
  baked floor and reopening the anti-rollback window.
- The `zid-sign` scan route reached the identity surface without a
  capability check; frame accumulation is now bounded, as is the
  envelope's `read_contributions` reservation, which previously sized
  itself from a declared u16 count rather than what the buffer could
  hold.
- Poisoned DB locks recover instead of panicking, so one transient
  failure no longer disables the device until restart.

### Removed

- Bitcoin, Nostr and atproto key derivation modules: 1,952 lines for
  three chains this device does not sign for, built into the shipped
  binary via the `active` feature and carrying a `bitcoin` 0.32
  dependency. Deliberate narrowing of scope, recoverable from history.
  The `Encryption::Bitcoin` FFI variant stays.
- Android screens and objects with no reachable callers, including the
  `SecurityStatusViewModel` chain and the standalone FVK export
  screens superseded by the inline path in `KeyDetailsPublicKeyScreen`.

## 0.10.0 - 2026-08-10

Minor, not patch. Picks up on-device delta module updates, the modpack
release tooling, the camera route that finally reaches the update confirm
screen, a voting-delegation display, a feature-gated ML-DSA hybrid
verifier, and developer-gated online mode - plus security-relevant fixes:
hedged signing nonces, package length malleability, and an SSH key
comparison that matched a substring instead of the parsed field.

### Features

- ed25519 general verifier + ZIP-32 seed fingerprint: standardizes the
  update/publisher verifier on ed25519 (zid-style identity), replacing the
  sr25519 default, and emits a proper 32-byte ZIP-32 `SeedFingerprint`
  (BLAKE2b, `mnemonic.to_seed`) at the export site so vizor/Keystone import
  no longer rejects it as not-32-bytes.
- Delegation-aware display for voting-delegation PCZTs: recognizes a Zcash
  voting-delegation PCZT by its shape (zero transparent inputs, one
  unsigned Ironwood governance action with a provably-zero output value)
  and shows a truthful "voting delegation -> hotkey, zero value"
  confirmation instead of a payment screen or an outright rejection. The
  send/payment path and its anti-tamper checks are untouched and still run
  first. Round id and amount stay in the encrypted memo and are not
  displayed.
- ed25519+ML-DSA hybrid verifier scaffold (feature-gated): adds
  `rust/pq_hybrid` with `HybridPublicKey`/`HybridSignature` and dual-verify
  AND semantics (both ed25519 and ML-DSA-65 must pass), behind the
  `pq-hybrid` feature (off by default). Kept out of the main workspace for
  now due to a `digest` pre-release pin clash with the zcash signer stack;
  builds and tests against its own lockfile.
- Hide online mode behind a 5-tap developer unlock: online mode (which
  breaks the air-gap) was always visible in Advanced Settings. It is now
  gated behind an Android developer-mode style gesture - 5 taps on the
  verifier certificate value within a short window reveal the toggle.
  Revealing only surfaces the option; enabling online mode still requires
  the existing explicit confirmation and authentication flow, and stays
  off by default.
- Release tooling for signed module packages: `prepare` / `[scan]` /
  `assemble` / `verify` commands split release production across three
  machines so no single step ever holds two release keys, with delta
  packaging (bsdiff + zstd) reporting a 9x size reduction on a real module
  pair.
- Apply delta module updates on-device: a module update carrying a delta
  payload is reconstructed from the installed base plus the delta, turning
  a module update into tens of KB over QR instead of 2 MB. Decompression
  is bounded by `MAX_MODULE_BYTES` so a swapped payload costs bounded work
  before failing the hash check.

### Fixes

- Package length malleability: a signed delta package accepted arbitrary
  appended bytes without invalidating the signature. The manifest now
  commits `payload_len` inside the signed region, and verification checks
  it before resolving the payload, so a wrong-sized payload is rejected
  before decompression ever runs.
- SSH key-ownership guard compared a substring of the blob instead of the
  parsed key field: the guard could be satisfied by embedding our key
  bytes in the attacker-controlled session identifier while the actual
  public-key field named a different identity. `classify_userauth` now
  returns the parsed key field and `sign_request` compares that field
  exactly.
- Checked length arithmetic in the SSH and manifest parsers: an
  attacker-declared length near `u32::MAX` could overflow on 32-bit
  targets (armeabi-v7a is a shipped ABI), passing bounds checks and then
  building a slice with `end < start` - a panic on hostile input on a real
  device. Now uses `checked_add` throughout.

### Security

- Hedged signing nonces (module OTA path), so host entropy is no longer
  load-bearing for key safety.

### Tests

- End-to-end release ceremony tests against the real modpack binary,
  covering the full package path, delta packaging, 2-of-3 threshold
  enforcement, and the changelog-required guard on `prepare`.
- cargo-fuzz targets for the untrusted-input parsers (`parse_prefix`,
  `verify_package`, `apply_patch`), plus a deterministic seeded-mutation
  smoke test that runs on every commit.
- Pinned the baked module version so bumping the shipped asset is a
  deliberate decision rather than something that silently regresses
  already-updated devices.

### Notes

- Module OTA ships inert in this release: `RELEASE_KEY_BYTES` is still
  all-zero, so `release_keys()` yields no trust anchor and
  `module_verify_package` fails closed with "release keys not
  provisioned." Scanning a module package will be refused. That is
  correct behavior, not a regression - the pipeline is complete but
  cannot be armed until the key ceremony happens.
