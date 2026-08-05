# Keystone-compatible PCZT signing for zigner

Goal: zigner speaks the same air-gap contract as Keystone so zafu, zashi and
vizor can treat it as a drop-in QR signer, and zigner stops blind-signing
digests.

## The contract (verified against zashi `harry/ironwood-migration` and vizor
`adam/qleak-pr73-orchard-librustzcash`, 2026-07)

Transport is **redacted-PCZT in, full signed PCZT out**:

1. Phone builds PCZT from proposal, runs the Prover role locally (Orchard,
   Ironwood `create_ironwood_proof`, Sapling - never the signer's job).
2. Phone runs the Redactor role: witnesses + proprietary
   `zcash_client_backend` fields cleared for global/orchard/ironwood/
   sapling/transparent (vizor `pczt.rs:287`).
3. Redacted PCZT ships over UR `zcash-pczt` / `crypto-pczt` (single) or
   `zcash-sign-batch` (vizor batch envelope, **1..35 messages**,
   `ZCASH_SIGN_BATCH_MAX_MESSAGES = 35`, `keystone.rs:47`).
4. Device parses the PCZT, **recomputes the sighash itself** (never trusts a
   phone-supplied digest), displays effects, signs.
5. Signature primitive for EVERY flow - regular Orchard spend, Ironwood V6
   spend, denomination-split prep tx, migration transfer, vote commitment
   (governance PCZT) - is a RedPallas spend-auth over the shielded sighash
   with per-action alpha, plus secp256k1 for transparent inputs. No proofs,
   no binding sig on the device (extraction/SpendFinalizer are phone-side,
   vizor `pczt.rs:401`).
6. Device returns the full signed PCZT. Batch return: per-message
   `kind = ZCASH_SIGN_MESSAGE_KIND_PCZT_V1`, `payload = signed_pczt_bytes`,
   `digest = sha256(signed_pczt_bytes)` (integrity checksum of the PCZT
   bytes, NOT the sighash - vizor `keystone.rs:553-566`).
7. Phone-side verification on return (zashi voting flow): extract sighash
   from signed PCZT, reject on mismatch with expected, extract per-action
   `spend_auth_sig`.

## Crate pins for interop

Both `rust/signer` (the shipped uniffi library) and `rust/pczt_signing`
(the protocol module compiled to wasm) now track the RELEASED crates.io
stack: `pczt` 0.9.2, orchard 0.15, `zcash_primitives` 0.30,
`zcash_protocol` 0.10, `zcash_transparent` 0.10, `zcash_keys` 0.16.

NU6.3 / Ironwood needs **no fork and no `zcash_unstable` build flag** any
more:
`pczt` 0.9.2 ships the Ironwood pool unconditionally, so the default build compiles
and tests the V6 signing path. The `pczt_signing_valar` spike that used to
prove this against the Valar fork branches has been deleted; its coverage
moved into `rust/pczt_signing/tests/{v6_ironwood,v6_ironwood_module}.rs`.

Wire-format note: since `pczt` 0.9 `Pczt::serialize` picks the minimal
encoding - the v1 PCZT encoding whenever the PCZT is v1-representable (V5
transaction with a canonical-empty Ironwood bundle), the v2 encoding
otherwise. V5 responses therefore stay byte-format-compatible with wallets
that predate the v2 encoding.

## Zigner implementation plan

New workspace crate `pczt_signing` (keep `transaction_signing/zcash.rs`
digest path for legacy QR type):

1. **Parse**: pczt crate Signer role over the redacted PCZT; reject
   non-redacted (witness data present) payloads.
2. **Verify + display**: recompute sighash; render outputs (address,
   amount, memo-present flag), fee, pool per action (orchard vs ironwood),
   net value change for the account.
3. **Sign**: derive USK from seed (existing zip32 path m/32'/133'/account'),
   spend-auth per action; secp256k1 for transparent inputs (existing
   bip44 path).
4. **Return**: serialize signed PCZT, fountain-encode UR.
5. **QR envelope**: new `tx_type` byte in the `[0x53][crypto][tx_type]`
   prelude for single PCZT, another for batch - old firmware fails closed
   with "unknown tx type" (verified behavior).
6. **Batch (phase 2)**: 1..35 messages per exchange mirroring
   `ZcashBatchMessageInput { id, pczt_bytes }` -> signed batch with sha256
   digests. Unlocks one-exchange Ironwood migration + vote bundles.

## Status (2026-07-06)

Done in `rust/pczt_signing` (standalone crate, all tested):
- Signer role: orchard spend-auth + transparent candidate-scan signing
- QR envelope: tx_type 0x03 (single) / 0x04 (batch, cap 35), fail-closed
  on unknown and legacy (0x02) types; response carries sha256 integrity
  digests per message (Keystone parity)
- summarize_request(): per-message confirmation data incl. orchard output
  values + recipients (zafu's redactor retains them)
- Interop proven: zafu-wasm produce+redact -> envelope -> this crate signs
  (batch of 2, ids echoed, digests verified) -> zafu-wasm finalize+extract
  -> valid v5 tx

Remaining:
- Workspace merge: `pczt_signing` is still a standalone `[workspace]`
  because the legacy resolver-1 workspace pins orchard 0.10 (via
  `frost-spend`). `rust/signer` itself is now on orchard 0.15 alongside it,
  so the two coexist in the same lockfile.
- Kotlin: uniffi surface for summarize_request/sign_request + confirm
  screen rendering PcztSummary; scan dispatcher routes tx_type 0x03/0x04.
- UR fountain framing on the response for large batches.

## Sequencing

- Store release (current firmware, blind digest signing): DONE - ships now,
  signs everything through Ironwood activation.
- Phase 1 (single PCZT verify+sign): after zcli `feat/pczt-builder` lands;
  no NU6.3 dependency for V5 txs.
- Phase 2 (batch + Ironwood V6): DONE against released `pczt` 0.9.2 - no
  fork, no build flag. Both the shipped `rust/signer` entry points
  (`inspect_zcash_pczt` / `sign_zcash_pczt`) and the wasm protocol module
  summarize and sign a V6 turnstile migration.
