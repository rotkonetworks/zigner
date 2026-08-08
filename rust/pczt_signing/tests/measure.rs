//! Measure the actual compact-signing payload win on our own fixtures.
mod common;
use common::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// zafu's fountain fragment size (zcash-worker default).
const FRAG: usize = 200;

fn frames(bytes: usize) -> usize {
    // bc-ur fountain: ceil(payload / fragment), the minimum emitted parts
    bytes.div_ceil(FRAG)
}

#[test]
fn report_compact_savings() {
    let fx = build_redacted_v6_migration();

    // request leg: today's redaction vs compact redaction
    let full = pczt::Pczt::parse(&fx.full_pczt).expect("full");
    let legacy_req = fx.redacted_pczt.len();
    let compact_req = redact_pczt_for_compact_signer(full)
        .serialize()
        .expect("serialize compact")
        .len();

    // response leg: full signed PCZT vs signatures-only
    let req = pczt_signing::envelope::encode_request_full(
        &pczt_signing::envelope::SignRequest::Single(pczt_signing::envelope::RequestMessage {
            id: b"m".to_vec(),
            pczt_bytes: fx.redacted_pczt.clone(),
        }),
        true,
    )
    .unwrap();
    let compact_resp = pczt_signing::sign_request(&req, MNEMONIC, 0, false)
        .unwrap()
        .len();
    let legacy_resp = pczt_signing::sign_redacted_pczt(&fx.redacted_pczt, MNEMONIC, 0, false)
        .unwrap()
        .len();

    println!("\n=== ONE v6 turnstile migration, {FRAG}B fragments ===");
    println!(
        "request : {legacy_req:>7} B ({:>3} frames) -> {compact_req:>7} B ({:>3} frames)   {:.2}x smaller",
        frames(legacy_req), frames(compact_req), legacy_req as f64 / compact_req as f64
    );
    println!(
        "response: {legacy_resp:>7} B ({:>3} frames) -> {compact_resp:>7} B ({:>3} frames)   {:.2}x smaller",
        frames(legacy_resp), frames(compact_resp), legacy_resp as f64 / compact_resp as f64
    );
    let l = legacy_req + legacy_resp;
    let c = compact_req + compact_resp;
    println!(
        "round   : {l:>7} B ({:>3} frames) -> {c:>7} B ({:>3} frames)   {:.2}x smaller",
        frames(l),
        frames(c),
        l as f64 / c as f64
    );
    println!("\n--- extrapolated to a 35-transaction migration batch ---");
    println!(
        "request : {:>4} frames -> {:>4} frames",
        frames(legacy_req * 35),
        frames(compact_req * 35)
    );
    println!(
        "response: {:>4} frames -> {:>4} frames",
        frames(legacy_resp * 35),
        frames(compact_resp * 35)
    );
    assert!(compact_req < legacy_req, "compact request must be smaller");
    assert!(
        compact_resp < legacy_resp,
        "compact response must be smaller"
    );
}
