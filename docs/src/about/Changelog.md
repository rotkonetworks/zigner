# Changelog

For full release artifacts (signed APKs, SHA256SUMS, ssh signatures), see
[GitHub Releases](https://github.com/rotkonetworks/zigner/releases).

## v0.4.1 — 2026-05-01

Security hardening pass + UI follow-up.

- FROST nonce reuse defense: replace `DefaultHasher` (engineerable
  collisions) with SHA-256 over the full nonce; store the full 32-byte
  fingerprint.
- Sticky FROST attestation flag is now actually enforced on note import.
  Once a device has held FROST keys it permanently refuses unattested
  Zcash note bundles.
- Anchor attestation length is strict (== 64 bytes for ed25519). A 96-byte
  FROST-style attestation can no longer fall through this path with its
  randomizer silently dropped.
- Encrypted backup AEAD: format version is bound into the auth tag via
  XChaCha20-Poly1305 associated data. Backups are bumped to v2; legacy v1
  ciphertexts still decrypt.
- CBOR parser depth-capped at 32 to defend against malicious deeply-nested
  QR payloads (stack-overflow DoS).
- `frost_backup` uses `OsRng` instead of `thread_rng` for salt + nonce.
- ZID auth rejects challenges older than 5 minutes or more than 60 seconds
  in the future.
- Pre-sign review screens (PCZT, FROST sign, Penumbra spend) now reveal
  the full recipient address on tap. Truncated form is the default for
  layout, but the full address is one tap away — needed because the
  trust model assumes the user reads the recipient before approving.

## v0.4.0 — 2026-04-30

First major Zafu-ecosystem release.

- FROST multisig: DKG (rounds 1–3) and signing (rounds 1–2) over animated
  QR codes — no relay server in the trust path.
- Anchor attestation: FROST groups sign a domain-separated digest of the
  anchor; signer rejects unattested anchors once the device has held
  FROST keys. Built on existing reddsa primitives — no custom crypto.
- Hot wallet derivation (`ur:zafu-hot-wallet`): deterministic 12-word
  BIP39 from the master seed for use in Zafu pro.
- ZID identity: site-scoped ed25519 challenge signing with cross-site
  correlation prevention via domain-separated derivation.
- Encrypted backup (`ur:zigner-backup`): XChaCha20-Poly1305 with backup
  key derived from the seed phrase.
- Animated UR QR using `raptorq` fountain codes for FROST DKG/sign,
  backups, and contacts.
- Default dark theme; full-bleed wallet QR on the landing screen.
- Per-multisig wallet renaming.
- Substrate export keys path disabled by default (Zcash-first).

## v0.2.x

Penumbra cold signing, transparent + Orchard PCZT inspection,
ZIP-316 UFVK export.

## v0.1.0

Initial Zigner release: Penumbra and Substrate signing on the Polkadot
Vault foundation. Zigner-branded UI; Rotko verifier key embedded for
anchor attestation roadmap.
