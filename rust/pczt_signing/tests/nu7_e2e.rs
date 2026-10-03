//! NU7 end to end: a genuine NU7 (branch 0x77190ad9) turnstile migration is
//! signed by the device from the redacted PCZT, the signatures are merged into
//! the wallet's retained PCZT, both bundles are proved, and the transaction is
//! extracted. Extraction verifies every spend-auth signature and the proofs
//! against the NU7 sighash, with the circuit chosen from each bundle's own
//! version (no verifying key is passed in), so a signature over the wrong
//! sighash - or a branch the stack mishandles - fails here.

mod common;

use common::{build_redacted_nu7_migration, MNEMONIC};
use pczt::roles::{
    prover::Prover, spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor,
};
use pczt_signing::consensus_gate::BRANCH_NU7;

fn compact_request(pczt: &[u8]) -> Vec<u8> {
    pczt_signing::envelope::encode_request_full(
        &pczt_signing::envelope::SignRequest::Single(pczt_signing::envelope::RequestMessage {
            id: b"nu7".to_vec(),
            pczt_bytes: pczt.to_vec(),
        }),
        true,
    )
    .expect("encode compact request")
}

#[test]
fn nu7_migration_signs_merges_proves_and_extracts() {
    let fx = build_redacted_nu7_migration();

    // device side: sign the redacted bytes that cross the airgap
    let resp = pczt_signing::sign_request(&compact_request(&fx.redacted_pczt), MNEMONIC, 0, false)
        .expect("device signs NU7");
    let parsed = pczt_signing::parse_compact_response(&resp).expect("parse response");

    // wallet side: merge into the retained PCZT, prove, finalize, extract
    let mut merged = pczt::Pczt::parse(&fx.full_pczt).expect("retained pczt");
    for m in &parsed.messages {
        for c in &m.signatures {
            merged = pczt_signing::apply_signature_contribution(merged, c).expect("merge");
        }
    }
    assert_eq!(*merged.global().consensus_branch_id(), BRANCH_NU7);

    // Both bundles of a V6 transaction prove under the post-NU6.3 circuit
    // (NU7 does not change it: zebra halo2.rs maps `Nu6_3 | Nu7` to one key).
    let pk =
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let proved = Prover::new(merged)
        .create_orchard_proof(&pk)
        .expect("orchard proof")
        .create_ironwood_proof(&pk)
        .expect("ironwood proof")
        .finish();

    let finalized = SpendFinalizer::new(proved)
        .finalize_spends()
        .expect("finalize");
    let tx = TransactionExtractor::new(finalized)
        .extract()
        .expect("extract: proofs + spend-auth + binding signatures verify under NU7");

    let mut bytes = Vec::new();
    tx.write(&mut bytes).expect("serialize");
    // v6 header: version 6 | 1<<31, little-endian
    assert_eq!(&bytes[0..4], &[0x06, 0x00, 0x00, 0x80]);
}
