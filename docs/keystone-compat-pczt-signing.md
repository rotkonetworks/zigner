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

Wallet side already exists: zcli `feat/pczt-builder` has producer +
extractor + redactor + UR fountain decoder, pinned to
`pczt` @ librustzcash rev `5333c01b` (features incl. `signer`),
orchard 0.12. **Zigner's signer module must pin the same rev** - PCZT
field-level compat matters more than crate age. NU6.3/Ironwood: rev bump to
the Valar fork branches once stable; V6 sighash recompute comes with it.

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
- Workspace merge: the legacy resolver-1 workspace pins orchard 0.10 and
  several deps of the new stack are yanked on crates.io (orchard 0.12.0,
  core2 0.3.x, halo2_gadgets 0.4.0 - locks seeded from zcli's
  feat/pczt-builder lockfile bypass this). Merge lands together with the
  NU6.3 rev bump.
- Kotlin: uniffi surface for summarize_request/sign_request + confirm
  screen rendering PcztSummary; scan dispatcher routes tx_type 0x03/0x04.
- UR fountain framing on the response for large batches.

## Sequencing

- Store release (current firmware, blind digest signing): DONE - ships now,
  signs everything through Ironwood activation.
- Phase 1 (single PCZT verify+sign): after zcli `feat/pczt-builder` lands;
  no NU6.3 dependency for V5 txs.
- Phase 2 (batch + Ironwood V6): when Valar crate branches stabilize;
  before NU6.3 activation for migration UX.
