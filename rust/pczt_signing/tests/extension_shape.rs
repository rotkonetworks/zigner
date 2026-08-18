//! Reproduce the EXACT compact-redaction shape the zafu extension emits, and
//! run it through `summarize` (the code the device's module wasm runs).
//!
//! The existing compact fixtures use the zigner-side contract: cv_net CLEARED
//! (recomputed by resolve_fields from a RETAINED spend value). But the shipped
//! zcli `redact_pczt_compact` does the opposite: it KEEPS cv_net and CLEARS
//! spend.value (redact_pczt_for_signer strips it for privacy). resolve_cv_net
//! skips when cv_net is present, so on paper both shapes resolve - this test
//! proves it against the same summarize path the device runs, so a regression
//! in the wire contract is caught here without a phone in the loop.
mod common;
use common::*;

use module_host::ModuleRuntime;
use pczt::roles::redactor::Redactor;
use pczt::Pczt;

const BUNDLED_MODULE_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../android/src/main/assets/modules/module0.wasm"
);

/// Mirror zcli `redact_pczt_for_signer` + `redact_pczt_compact`: keep cv_net,
/// CLEAR spend.value, clear cmx, replace enc_ciphertext with memo plaintext.
fn redact_extension_shape(pczt: Pczt) -> Pczt {
    Redactor::new(pczt)
        .redact_global_with(|mut g| {
            g.clear_proprietary();
        })
        .redact_orchard_with(|mut o| {
            o.redact_actions(|mut a| {
                a.clear_spend_witness();
                a.clear_spend_zip32_derivation();
                a.clear_spend_dummy_sk();
                a.clear_spend_proprietary();
                a.clear_spend_rseed();
                a.clear_spend_rho();
                a.clear_spend_recipient();
                a.clear_spend_value(); // extension clears this (privacy)
                a.clear_spend_fvk();
                // cv_net deliberately KEPT (extension), so resolve_cv_net skips.
                a.clear_output_zip32_derivation();
                a.clear_output_user_address();
                a.clear_output_proprietary();
                a.clear_cmx();
                a.replace_enc_ciphertext_with_memo_plaintext([0u8; 512]);
            });
            o.clear_anchor();
        })
        .redact_ironwood_with(|mut o| {
            o.redact_actions(|mut a| {
                a.clear_spend_witness();
                a.clear_spend_zip32_derivation();
                a.clear_spend_dummy_sk();
                a.clear_spend_proprietary();
                a.clear_spend_rseed();
                a.clear_spend_rho();
                a.clear_spend_recipient();
                a.clear_spend_value(); // extension clears this (privacy)
                a.clear_spend_fvk();
                // cv_net deliberately KEPT (extension).
                a.clear_cmx();
                a.replace_enc_ciphertext_with_memo_plaintext([0u8; 512]);
            });
            o.clear_anchor();
        })
        .redact_transparent_with(|mut t| {
            t.redact_outputs(|mut o| {
                o.clear_user_address();
                o.clear_proprietary();
            });
        })
        .finish()
}

#[test]
fn extension_compact_shape_summarizes() {
    let fx = build_redacted_v6_migration();
    let full = Pczt::parse(&fx.full_pczt).expect("parse full pczt");
    let redacted = redact_extension_shape(full);
    let bytes = redacted.serialize().expect("serialize extension-shape pczt");

    match pczt_signing::summarize(&bytes) {
        Ok(s) => {
            eprintln!(
                "summarize OK: orchard={} ironwood={} t_in={} fee={:?} outs={}",
                s.orchard_actions,
                s.ironwood_actions,
                s.transparent_inputs,
                s.fee_zat,
                s.outputs.len()
            );
        }
        Err(e) => panic!("EXTENSION-SHAPE summarize FAILED: {e:?}"),
    }
}

/// The decisive one: drive the SHIPPED module0.wasm (the exact bytes the device
/// runs) with the extension's compact shape, under wasmi. If the device fails
/// "protocol module cannot parse this request", it fails HERE too - no phone.
#[test]
fn extension_compact_shape_summarizes_under_wasmi() {
    let wasm = std::fs::read(BUNDLED_MODULE_WASM)
        .unwrap_or_else(|e| panic!("bundled module wasm missing at {BUNDLED_MODULE_WASM}: {e}"));
    let mut rt = ModuleRuntime::load(&wasm).expect("instantiate module under wasmi");

    let fx = build_redacted_v6_migration();
    let full = Pczt::parse(&fx.full_pczt).expect("parse full pczt");
    let redacted = redact_extension_shape(full);
    let bytes = redacted.serialize().expect("serialize extension-shape pczt");

    for tx_type in [0x03u8, 0x05u8] {
        let mut payload = vec![0x53, 0x04, tx_type];
        payload.extend_from_slice(&bytes);
        match rt.summarize_request(&payload) {
            Ok(blob) => eprintln!(
                "wasm summarize OK (tx_type={tx_type:#04x}): {} bytes",
                blob.len()
            ),
            Err(e) => panic!(
                "SHIPPED WASM summarize FAILED on extension shape (tx_type={tx_type:#04x}): {e:?}"
            ),
        }
    }
}
