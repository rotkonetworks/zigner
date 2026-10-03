//! The consensus gate refuses, before anything is displayed, every PCZT this
//! build cannot verify - and keeps NU7 off on mainnet until its activation
//! height is compiled in.
//!
//! Fixtures are real NU6.3 PCZTs with the consensus branch id patched in
//! place. postcard encodes the u32 as LEB128; every branch id used here is
//! >= 2^28, so each encodes to exactly 5 bytes and the patch keeps all later
//! offsets intact.

mod common;

use common::{
    build_redacted_nu7_migration, build_redacted_v5_send, build_redacted_v6_migration, MNEMONIC,
};
use pczt_signing::consensus_gate::{self, BRANCH_NU6_3, BRANCH_NU7};

fn leb128(mut v: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn with_branch(pczt: &[u8], from: u32, to: u32) -> Vec<u8> {
    let (needle, repl) = (leb128(from), leb128(to));
    assert_eq!(needle.len(), repl.len());
    let hits: Vec<usize> = pczt
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle.as_slice())
        .map(|(i, _)| i)
        .collect();
    // The global branch id is the first occurrence; refuse to guess if the
    // encoding shows up anywhere ambiguous before it.
    let at = *hits.first().expect("branch id present in fixture");
    let mut out = pczt.to_vec();
    out[at..at + repl.len()].copy_from_slice(&repl);
    let parsed = pczt::Pczt::parse(&out).expect("patched PCZT still parses");
    assert_eq!(
        *parsed.global().consensus_branch_id(),
        to,
        "patched the global field"
    );
    out
}

fn err(r: Result<pczt_signing::PcztSummary, pczt_signing::Error>) -> String {
    format!("{:?}", r.expect_err("must be refused"))
}

#[test]
fn nu6_3_v6_is_accepted() {
    let fx = build_redacted_v6_migration();
    pczt_signing::summarize(&fx.redacted_pczt).expect("NU6.3 V6 summarizes");
}

#[test]
fn unknown_branch_is_refused_before_display() {
    let fx = build_redacted_v6_migration();
    let bad = with_branch(&fx.redacted_pczt, BRANCH_NU6_3, 0xdead_beef);
    let e = err(pczt_signing::summarize(&bad));
    assert!(e.contains("unsupported consensus branch 0xdeadbeef"), "{e}");
}

// This build is meant to verify NU7. If a dependency downgrade ever loses
// that, the gate would silently start refusing every NU7 PCZT - fail here
// instead.
#[test]
fn this_build_verifies_nu7() {
    assert!(
        zcash_protocol::consensus::BranchId::try_from(BRANCH_NU7).is_ok(),
        "linked zcash_protocol does not know NU7 (0x77190ad9)"
    );
}

#[test]
fn v6_on_a_pre_nu6_3_branch_is_refused() {
    let fx = build_redacted_v6_migration();
    let bad = with_branch(
        &fx.redacted_pczt,
        BRANCH_NU6_3,
        consensus_gate::BRANCH_NU6_2,
    );
    let e = err(pczt_signing::summarize(&bad));
    assert!(e.contains("V6 transaction on pre-NU6.3 branch"), "{e}");
}

// Activation by block height, mainnet only: NU7 stays off until
// MAINNET_NU7_ACTIVATION is set. Testnets (public + staging, with different
// activation tables) are left to their own consensus.
#[test]
fn mainnet_nu7_waits_for_its_activation_height() {
    let fx = build_redacted_v6_migration();
    let nu7 = pczt::Pczt::parse(&with_branch(&fx.redacted_pczt, BRANCH_NU6_3, BRANCH_NU7)).unwrap();
    let nu6_3 = pczt::Pczt::parse(&fx.redacted_pczt).unwrap();

    assert!(consensus_gate::check_activation(&nu6_3, true).is_ok());
    assert!(
        consensus_gate::check_activation(&nu7, false).is_ok(),
        "testnet not height-gated"
    );
    match consensus_gate::MAINNET_NU7_ACTIVATION {
        None => {
            let e = format!(
                "{:?}",
                consensus_gate::check_activation(&nu7, true).unwrap_err()
            );
            assert!(e.contains("not active on mainnet"), "{e}");
        }
        Some(h) => {
            let expiry = *nu7.global().expiry_height();
            let expect_ok = expiry == 0 || expiry >= h;
            assert_eq!(
                consensus_gate::check_activation(&nu7, true).is_ok(),
                expect_ok
            );
        }
    }
}

// The V5 control fixture still passes the gate: older verifiable branches are
// the network's call, not ours.
#[test]
fn v5_on_older_branch_is_accepted() {
    let fx = build_redacted_v5_send();
    pczt_signing::summarize(&fx.redacted_pczt).expect("V5 NU6.2 summarizes");
}

// A genuine NU7 PCZT (builder targeting branch 0x77190ad9) is displayed with
// every gate applied, and signed on testnet - the network the fixture keys
// are derived for.
#[test]
fn genuine_nu7_pczt_summarizes_and_signs_on_testnet() {
    let fx = build_redacted_nu7_migration();
    let pczt = pczt::Pczt::parse(&fx.redacted_pczt).unwrap();
    assert_eq!(*pczt.global().consensus_branch_id(), BRANCH_NU7);

    let summary = pczt_signing::summarize(&fx.redacted_pczt).expect("NU7 summarizes");
    assert_eq!(
        summary.fee_zat,
        Some(fx.fee),
        "fee is computed, not unknown"
    );
    assert!(summary.ironwood_actions > 0);

    pczt_signing::sign_redacted_pczt(&fx.redacted_pczt, MNEMONIC, 0, false)
        .expect("NU7 signs on testnet");
}

// Mainnet keeps NU7 off until MAINNET_NU7_ACTIVATION is compiled in.
#[test]
fn genuine_nu7_pczt_is_refused_on_mainnet_until_activation() {
    if consensus_gate::MAINNET_NU7_ACTIVATION.is_some() {
        return;
    }
    let fx = build_redacted_nu7_migration();
    let e = format!(
        "{:?}",
        pczt_signing::sign_redacted_pczt(&fx.redacted_pczt, MNEMONIC, 0, true)
            .expect_err("refused on mainnet")
    );
    assert!(e.contains("not active on mainnet"), "{e}");
}
