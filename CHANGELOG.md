# Changelog

All notable changes to zigner are documented in this file.

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
