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

## Compact signatures-only responses (2026-08-08)

Upstream port of the Ironwood migration performance work (librustzcash PRs
2535/2602/2643/2662; Keystone firmware PRs 2207/2213/2211): the device can now
answer a signing request with **only the spend-auth signatures it produced**
instead of the full signed PCZT. For the 35-PCZT migration that shrinks the
return QR from ~132 KB / 662 fragments to ~6.5 KB / 33 fragments (~20x).

How it works (new `tx_type` bytes on the `[0x53][0x04][...]` prelude, same
"deliberately dumb" framing):

| tx_type | direction | payload |
|---------|-----------|---------|
| 0x03 / 0x04 | request | single / batch of redacted PCZTs (unchanged) |
| 0x05 / 0x06 | request | same bodies as 0x03 / 0x04, but **compact**: the device answers 0x07 / 0x08 |
| 0x07 / 0x08 | response | compact version prefix + per-PCZT signature contributions |

A contribution is `(pool:u8, action_index:u32, signature:64)` with
`pool` = 0 Orchard / 1 Ironwood - the same (value_pool, action_index,
signature) triple as upstream `pczt::roles::signer::SpendAuthSignature`
(PR 2602), so the same primitives shade both sides of the airgap:
`extract_orchard_spend_auth_signatures` on the device,
`Signer::apply_orchard_spend_auth_signature` / `orchard::pczt::Action::apply_signature`
in the wallet. Signatures are positional per PCZT in request order; batch
responses echo the wallet-chosen ids. The response opens with a version
string (Keystone PR 2211 parity) so a wallet can refuse a shape it cannot
merge.

Batch cap raised 35 -> 40 (Keystone `ZCASH_BATCH_MAX_PCZTS`); old firmware
still fails closed on unknown tx_types, so a wallet that gets an error after
asking 0x05/0x06 must retry 0x03/0x04. Compact is only offered for
shielded-only PCZTs: a compact request containing transparent inputs is
refused loudly (the transport cannot express secp256k1 input signatures) -
the wallet falls back to the full signed-PCZT response.

Device-side signing is identical in both modes: same redacted-PCZT parse,
same on-device sighash recomputation and display gates, same verify-before-
sign. The compact response is derived from the finished PCZT
(`pczt::roles::signer::extract_orchard_spend_auth_signatures`), whose
signatures are the randomized RedPallas spend-auth signatures - the wallet
verifies each one against the action `rk` over the shielded sighash when it
merges (proven by `tests/v6_ironwood.rs::compact_v6_migration_returns_signatures_only`).

Implementation state: shipped in `rust/pczt_signing` (envelope + sign path +
wallet-side `parse_compact_response`), the wasm protocol module (module0.wasm
rebuilt), the Android module path (scan routing accepts 0x05/0x06; module
screen flags compact responses), and tested native + under wasmi. QRs still
ride the existing `ur:zigner-module` fountain; **no zafu change yet** -
zafu/zcli need to (a) emit 0x05/0x06 when the signer is module-capable,
(b) parse 0x07/0x08 and merge the contributions into the PCZT it kept
(via `Signer::apply_orchard_spend_auth_signature` / an Ironwood-aware
`complete_*_pczt` role), then run SpendFinalizer + TransactionExtractor.

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
