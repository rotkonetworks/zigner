//! Envelope wire-format tests: round-trips, caps, fail-closed behavior.

use pczt_signing::envelope::*;

fn msg(id: &[u8], body: &[u8]) -> RequestMessage {
    RequestMessage { id: id.to_vec(), pczt_bytes: body.to_vec() }
}

#[test]
fn single_round_trips() {
    let req = SignRequest::Single(msg(b"", b"pczt-bytes"));
    let parsed = parse_request(&encode_request(&req).unwrap()).unwrap();
    assert_eq!(parsed, req);
}

#[test]
fn batch_round_trips() {
    let req = SignRequest::Batch(vec![msg(b"a", b"one"), msg(b"bb", b"two-two")]);
    let parsed = parse_request(&encode_request(&req).unwrap()).unwrap();
    assert_eq!(parsed, req);
}

#[test]
fn batch_cap_is_35() {
    let m: Vec<_> = (0..36).map(|i| msg(&[i as u8], b"x")).collect();
    assert!(matches!(
        encode_request(&SignRequest::Batch(m)),
        Err(EnvelopeError::BatchCount(36))
    ));
    // and 35 is fine
    let m: Vec<_> = (0..35).map(|i| msg(&[i as u8], b"x")).collect();
    let parsed = parse_request(&encode_request(&SignRequest::Batch(m)).unwrap()).unwrap();
    assert_eq!(parsed.messages().len(), 35);
}

#[test]
fn unknown_tx_type_fails_closed() {
    assert!(matches!(
        parse_request(&[PRELUDE, CRYPTO_TYPE_ZCASH, 0x77, 1, 2, 3]),
        Err(EnvelopeError::UnknownTxType(0x77))
    ));
}

#[test]
fn legacy_digest_tx_type_is_not_ours() {
    // 0x02 is the legacy digest request - this parser must refuse it so the
    // dispatcher routes it to the old path, never half-parses it as PCZT.
    assert!(matches!(
        parse_request(&[PRELUDE, CRYPTO_TYPE_ZCASH, 0x02, 0, 0]),
        Err(EnvelopeError::UnknownTxType(0x02))
    ));
}

#[test]
fn truncated_batch_fails() {
    let good = encode_request(&SignRequest::Batch(vec![msg(b"a", b"payload")])).unwrap();
    for cut in 4..good.len() {
        assert!(parse_request(&good[..cut]).is_err(), "cut at {cut} must fail");
    }
}

#[test]
fn response_round_trips_with_digests() {
    let m = ResponseMessage {
        id: b"m-9".to_vec(),
        digest: integrity_digest(b"signed"),
        signed_pczt: b"signed".to_vec(),
    };
    let parsed = parse_response(&encode_response(&[m.clone()], true).unwrap()).unwrap();
    assert_eq!(parsed, vec![m]);
}
