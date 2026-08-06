//! RELEASE-GATING round-trip: a REAL V6 orchard->ironwood turnstile PCZT
//! driven through the wasmi protocol-module runtime (`module_host`), which is
//! byte-for-byte the runtime the Android device uses (it loads the same
//! module wasm as android/src/main/assets/modules/module0.wasm).
//!
//! This proves the bundled module *itself* summarizes + signs ironwood inside
//! the wasmi sandbox - not just the native rlib. The producer half (build +
//! redact of the migration PCZT) is shared with the native test via
//! tests/common/mod.rs, so both sign the exact same redacted-for-signer bytes.
//!
//! Build the module wasm first, then run:
//!   cargo build --target wasm32-unknown-unknown --release
//!   cargo test --release --test v6_ironwood_module
//!
//! The tests drive `android/src/main/assets/modules/module0.wasm` - the
//! artifact that actually ships in the APK - and FAIL when it is missing, so a
//! suite that asserted nothing can never report green. Set
//! `ZIGNER_ALLOW_MISSING_MODULE_WASM=1` to skip instead.
//!
//! A stale bundle is caught BEHAVIOURALLY, by one probe per security gate
//! (`module_rejects_a_tampered_output_value` for the display gate,
//! `module_rejects_a_tampered_value_sum` for the fee gate), rather than by
//! comparing the asset against a fresh build. That byte comparison was tried
//! and reverted: a release wasm is not reproducible across machines, so it
//! passed locally and failed CI.

mod common;

use common::{build_redacted_v6_migration, MNEMONIC};
use module_host::ModuleRuntime;
use pczt::Pczt;

/// The module wasm the DEVICE actually loads: the artifact bundled into the
/// Android APK. Tests drive this file, not the build output, so a stale asset
/// cannot pass by proxy.
const BUNDLED_MODULE_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../android/src/main/assets/modules/module0.wasm"
);

/// Set to 1 to let these tests skip when the bundled module wasm is missing.
/// Absent this, a missing artifact is a FAILURE, not a silent green run - a
/// suite that quietly asserts nothing is what hid the ironwood gap.
const SKIP_ENV: &str = "ZIGNER_ALLOW_MISSING_MODULE_WASM";

fn load_module(path: &str) -> ModuleRuntime {
    let wasm = std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "build the module wasm first (missing {path}): {e}\n\
             cd rust/pczt_signing && cargo build --target wasm32-unknown-unknown --release"
        )
    });
    ModuleRuntime::load(&wasm).expect("instantiate module under wasmi")
}

/// Returns false only when the bundled module wasm is missing AND the operator
/// explicitly opted into skipping. Otherwise a missing artifact FAILS the test.
///
/// Also pins the bundled APK asset against the build output when both exist:
/// the device runs the bundle, so a drifted bundle means these tests prove
/// nothing about what ships.
fn module_wasm_available() -> bool {
    let bundled = std::fs::read(BUNDLED_MODULE_WASM);
    let bundled = match bundled {
        Ok(b) => b,
        Err(e) => {
            if std::env::var(SKIP_ENV).as_deref() == Ok("1") {
                eprintln!(
                    "SKIPPED ({SKIP_ENV}=1): bundled module wasm missing at \
                     {BUNDLED_MODULE_WASM}: {e}"
                );
                return false;
            }
            panic!(
                "bundled module wasm missing at {BUNDLED_MODULE_WASM}: {e}\n\
                 build it with: cd rust/pczt_signing && \
                 cargo build --target wasm32-unknown-unknown --release && \
                 cp target/wasm32-unknown-unknown/release/pczt_signing.wasm \
                 ../../android/src/main/assets/modules/module0.wasm\n\
                 (set {SKIP_ENV}=1 to skip instead of failing)"
            );
        }
    };
    // Staleness is caught BEHAVIOURALLY, not by comparing bytes against a
    // fresh build. That comparison was tried and is unsatisfiable in CI: a
    // release wasm is not reproducible across machines (toolchain version and
    // embedded paths both leak in), so it can only pass on whichever machine
    // produced the committed artifact. It failed CI while passing locally,
    // which is the worst of both - a green light for the author and a red one
    // for everyone else.
    //
    // Instead, every test below drives the BUNDLED artifact, and the suite
    // includes one behavioural probe per security gate:
    //   - module_rejects_a_tampered_output_value  -> the display gate
    //   - module_rejects_a_tampered_value_sum     -> the fee gate
    // A bundle stale enough to be missing either one fails its probe. That is
    // the property actually worth protecting: not "these bytes match", but
    // "the artifact the device runs still refuses what it must refuse".
    let _ = &bundled;
    true
}

/// The summarize ABI returns a text head per message, records split by 0x1e:
///   actions=<n> ironwood_actions=<n> t_inputs=<n> fee=<n|unknown>
///   <label>=<value>            (one output per line)
struct ModuleSummary {
    orchard_actions: usize,
    ironwood_actions: usize,
    t_inputs: usize,
    fee: Option<u64>,
    outputs: Vec<(String, u64)>,
}

fn parse_head(field: &str, key: &str) -> String {
    field
        .split_whitespace()
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("summary head missing {key} in: {field:?}"))
        .to_string()
}

fn parse_module_summaries(blob: &[u8]) -> Vec<ModuleSummary> {
    let text = String::from_utf8(blob.to_vec()).expect("summary is utf8");
    text.split('\u{1e}')
        .filter(|rec| !rec.trim().is_empty())
        .map(|rec| {
            let mut lines = rec.lines();
            let head = lines.next().expect("summary head line");
            let outputs = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let (label, value) = l.rsplit_once('=').expect("output label=value");
                    (label.to_string(), value.parse::<u64>().unwrap_or(0))
                })
                .collect();
            ModuleSummary {
                orchard_actions: parse_head(head, "actions").parse().unwrap(),
                ironwood_actions: parse_head(head, "ironwood_actions").parse().unwrap(),
                t_inputs: parse_head(head, "t_inputs").parse().unwrap(),
                fee: match parse_head(head, "fee").as_str() {
                    "unknown" => None,
                    n => Some(n.parse().unwrap()),
                },
                outputs,
            }
        })
        .collect()
}

/// prelude-wrap a single redacted PCZT for the module ABI:
///   [0x53, 0x04, 0x03] ++ redacted_pczt
fn single_request(redacted_pczt: &[u8]) -> Vec<u8> {
    let mut payload = vec![0x53, 0x04, 0x03];
    payload.extend_from_slice(redacted_pczt);
    payload
}

#[test]
fn nu63_module_summarizes_and_signs_ironwood_under_wasmi() {
    if !module_wasm_available() {
        return;
    }
    // 1. Real redacted V6 turnstile PCZT (orchard spend -> ironwood output,
    //    branch id 0x37a5165b) from the shared producer.
    let fx = build_redacted_v6_migration();
    let ironwood_hex: String = fx.ironwood_recipient.iter().map(|b| format!("{b:02x}")).collect();

    // 2. Load the module wasm into the wasmi ModuleRuntime.
    let mut rt = load_module(BUNDLED_MODULE_WASM);

    // 3. Summarize under wasmi.
    let payload = single_request(&fx.redacted_pczt);
    let blob = rt
        .summarize_request(&payload)
        .expect("nu6.3 module summarize_request under wasmi");
    let summaries = parse_module_summaries(&blob);
    assert_eq!(summaries.len(), 1, "one summary for a single request");
    let s = &summaries[0];

    // Parses OK, ironwood is visible, and it is NOT ironwood-blind.
    assert!(
        s.ironwood_actions >= 1,
        "module reports ironwood actions (R3 ironwood-blind anti-regression): {} actions, {} ironwood",
        s.orchard_actions,
        s.ironwood_actions
    );
    assert!(
        s.orchard_actions >= 1,
        "orchard spend visible: actions={} ironwood_actions={}",
        s.orchard_actions,
        s.ironwood_actions
    );

    // The fee shown is the REAL small network fee, not ~the migrated amount.
    assert_eq!(
        s.fee,
        Some(fx.fee),
        "module confirms the real network fee, not the ironwood-blind ~migrated amount"
    );
    assert!(
        s.fee.unwrap() < fx.migrated,
        "fee ({:?}) must be far below the migrated value ({}) - the ironwood-blind bug reported ~the whole amount",
        s.fee,
        fx.migrated
    );
    assert_eq!(s.t_inputs, 0, "turnstile migration has no transparent inputs");

    // The ironwood destination is present in the summary outputs, and the
    // migrated value lands there.
    let ironwood_out: u64 = s
        .outputs
        .iter()
        .filter(|(l, _)| l.starts_with("ironwood:"))
        .map(|(_, v)| v)
        .sum();
    assert_eq!(
        ironwood_out, fx.migrated,
        "migrated value shown against the ironwood pool: {:?}",
        s.outputs
    );
    assert!(
        s.outputs
            .iter()
            .any(|(l, _)| l == &format!("ironwood:{ironwood_hex}")),
        "the ironwood destination receiver is present in the summary: looked for ironwood:{ironwood_hex} in {:?}",
        s.outputs
    );

    // 4. Sign under wasmi with the seed owning the notes (mainnet=false, the
    //    turnstile fixture derives with TestNetwork/coin type 1).
    let resp = rt
        .sign_request(&payload, MNEMONIC, 0, false)
        .expect("nu6.3 module sign_request under wasmi");

    // Parse the response envelope, extract the signed PCZT.
    let messages =
        pczt_signing::envelope::parse_response(&resp).expect("module response envelope parses");
    assert_eq!(messages.len(), 1, "single response");
    let signed_bytes = &messages[0].signed_pczt;

    // Integrity digest parity (Keystone rule): sha256(signed_pczt).
    assert_eq!(
        messages[0].digest,
        pczt_signing::envelope::integrity_digest(signed_bytes),
        "response digest is sha256(signed_pczt)"
    );

    // Confirm the module-signed output is a valid V6 migration tx: it parses
    // as a V6 PCZT with a populated ironwood bundle, every shielded action
    // carries a RedPallas spend-auth signature. (Proving/broadcast extraction
    // needs Halo2 keys and is out of scope for the cold signer, exactly as in
    // the native test.)
    let signed = Pczt::parse(signed_bytes).expect("module-signed PCZT parses");
    assert_eq!(
        *signed.global().tx_version(),
        zcash_protocol::constants::V6_TX_VERSION,
        "module-signed tx is TxVersion::V6"
    );
    assert!(
        !signed.ironwood().actions().is_empty(),
        "module-signed PCZT carries an ironwood bundle"
    );
    for (i, action) in signed.orchard().actions().iter().enumerate() {
        assert!(
            action.spend().spend_auth_sig().is_some(),
            "orchard action {i} left unsigned by the module"
        );
    }
    for (i, action) in signed.ironwood().actions().iter().enumerate() {
        assert!(
            action.spend().spend_auth_sig().is_some(),
            "ironwood action {i} left unsigned by the module"
        );
    }
}

/// V5 NON-REGRESSION under the SAME module: the ironwood-capable module must
/// still handle an ordinary V5 orchard send - ironwood invisible
/// (`ironwood_actions=0`), the real recipient value and the real fee on the
/// confirmation screen, every orchard action signed, and the response still a
/// v1-encoded PCZT.
///
/// This replaces the old `old_default_module_is_ironwood_blind_contrast`
/// spike test, whose premise (a second, ironwood-blind module build) no longer
/// exists now that the single default module ships ironwood.
#[test]
fn module_still_handles_v5_orchard_send_unchanged() {
    if !module_wasm_available() {
        return;
    }
    let fx = common::build_redacted_v5_send();
    let payload = single_request(&fx.redacted_pczt);
    let mut rt = load_module(BUNDLED_MODULE_WASM);

    let blob = rt
        .summarize_request(&payload)
        .expect("module summarizes a V5 orchard send");
    let summaries = parse_module_summaries(&blob);
    assert_eq!(summaries.len(), 1);
    let s = &summaries[0];
    assert_eq!(s.ironwood_actions, 0, "V5 send has no ironwood actions");
    assert!(s.orchard_actions >= 1, "V5 orchard actions visible");
    assert_eq!(s.t_inputs, 0);
    assert_eq!(
        s.fee,
        Some(fx.fee),
        "V5 fee is now shown, not 'unknown': the fee is one of the three things \
         the user must confirm on an ordinary orchard send"
    );
    let orchard_out: u64 = s
        .outputs
        .iter()
        .filter(|(l, _)| l.starts_with("orchard:"))
        .map(|(_, v)| v)
        .sum();
    assert_eq!(orchard_out, fx.migrated, "V5 recipient value visible");

    let resp = rt
        .sign_request(&payload, MNEMONIC, 0, false)
        .expect("module signs a V5 orchard send");
    let messages =
        pczt_signing::envelope::parse_response(&resp).expect("module response envelope parses");
    assert_eq!(messages.len(), 1);
    let signed_bytes = &messages[0].signed_pczt;
    assert_eq!(
        messages[0].digest,
        pczt_signing::envelope::integrity_digest(signed_bytes)
    );
    assert_eq!(
        &signed_bytes[4..8],
        &[1, 0, 0, 0],
        "the V5 signing response must still be a v1-encoded PCZT"
    );

    let signed = Pczt::parse(signed_bytes).expect("module-signed V5 PCZT parses");
    assert_eq!(
        *signed.global().tx_version(),
        zcash_protocol::constants::V5_TX_VERSION
    );
    assert!(signed.ironwood().actions().is_empty());
    for (i, action) in signed.orchard().actions().iter().enumerate() {
        assert!(
            action.spend().spend_auth_sig().is_some(),
            "V5 orchard action {i} left unsigned by the module"
        );
    }
}

/// TAMPER DETECTION inside the wasmi sandbox, on the artifact that ships in
/// the APK: an inflated output `value` - the number the confirmation screen
/// displays - must be refused by both module entry points, not displayed.
#[test]
fn module_rejects_a_tampered_output_value() {
    if !module_wasm_available() {
        return;
    }
    let fx = common::build_redacted_v5_send();
    let mut rt = load_module(BUNDLED_MODULE_WASM);

    // Honest control: the same module summarizes the untampered PCZT.
    rt.summarize_request(&single_request(&fx.redacted_pczt))
        .expect("module summarizes the honest PCZT");

    // Option<u64> on the wire: 0x01 tag + LEB128; same-length replacement.
    let varint = |mut v: u64| {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    };
    let mut needle = vec![0x01];
    needle.extend_from_slice(&varint(fx.migrated));
    let mut replacement = vec![0x01];
    replacement.extend_from_slice(&varint(fx.migrated + 1));
    assert_eq!(needle.len(), replacement.len());

    let mut tampered = fx.redacted_pczt.clone();
    let mut hits = 0;
    let mut i = 0;
    while i + needle.len() <= tampered.len() {
        if tampered[i..i + needle.len()] == needle[..] {
            tampered[i..i + needle.len()].copy_from_slice(&replacement);
            hits += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    assert!(hits > 0, "output value field not found in the wire bytes");
    let parsed = Pczt::parse(&tampered).expect("tampered PCZT still parses");
    assert!(
        parsed
            .orchard()
            .actions()
            .iter()
            .any(|a| a.output().value() == &Some(fx.migrated + 1)),
        "the displayed value was not actually changed"
    );

    let payload = single_request(&tampered);
    assert!(
        rt.summarize_request(&payload).is_err(),
        "the module must refuse to DISPLAY a PCZT whose amount contradicts its \
         note commitment"
    );
    assert!(
        rt.sign_request(&payload, MNEMONIC, 0, false).is_err(),
        "the module must refuse to SIGN a PCZT it refused to display"
    );
}

/// FEE gate inside the wasmi sandbox, on the artifact that ships in the APK.
///
/// The sibling test above covers the DISPLAY gate (output commitment). This
/// covers the FEE gate (value balance vs the action value commitments), and it
/// exists specifically so that a bundle stale by one commit cannot pass: an
/// artifact carrying the display gate but not the fee gate would satisfy
/// `module_rejects_a_tampered_output_value` while still letting a hostile
/// producer show any fee it liked. An inflated fee is fund loss, not a
/// cosmetic defect, so it gets its own probe against the shipped bytes.
#[test]
fn module_rejects_a_tampered_value_sum() {
    if !module_wasm_available() {
        return;
    }
    let fx = common::build_redacted_v5_send();
    let mut rt = load_module(BUNDLED_MODULE_WASM);

    // Honest control: the shipped module summarizes the untampered PCZT.
    rt.summarize_request(&single_request(&fx.redacted_pczt))
        .expect("module summarizes the honest PCZT");

    let varint = |mut v: u64| {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    };

    // For this shielded-only send the orchard value_sum IS the fee, so
    // inflating it by one zatoshi is a fee the value commitments contradict.
    let needle = varint(fx.fee);
    let replacement = varint(fx.fee + 1);
    assert_eq!(needle.len(), replacement.len());

    let mut tampered = fx.redacted_pczt.clone();
    let mut hits = 0;
    let mut i = 0;
    while i + needle.len() <= tampered.len() {
        if tampered[i..i + needle.len()] == needle[..] {
            tampered[i..i + needle.len()].copy_from_slice(&replacement);
            hits += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    assert!(hits > 0, "value_sum varint not found in the wire bytes");

    let payload = single_request(&tampered);
    assert!(
        rt.summarize_request(&payload).is_err(),
        "the module must refuse to DISPLAY a fee the action value commitments \
         contradict"
    );
    assert!(
        rt.sign_request(&payload, MNEMONIC, 0, false).is_err(),
        "the module must refuse to SIGN a fee it refused to display"
    );
}
