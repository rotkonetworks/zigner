//! Envelope wire-format tests: round-trips, caps, fail-closed behavior.

use pczt_signing::envelope::*;

fn msg(id: &[u8], body: &[u8]) -> RequestMessage {
    RequestMessage {
        id: id.to_vec(),
        pczt_bytes: body.to_vec(),
    }
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
fn batch_cap_is_40() {
    let m: Vec<_> = (0..41).map(|i| msg(&[i as u8], b"x")).collect();
    assert!(matches!(
        encode_request(&SignRequest::Batch(m)),
        Err(EnvelopeError::BatchCount(41))
    ));
    // and 40 is fine
    let m: Vec<_> = (0..40).map(|i| msg(&[i as u8], b"x")).collect();
    let parsed = parse_request(&encode_request(&SignRequest::Batch(m)).unwrap()).unwrap();
    assert_eq!(parsed.messages().len(), 40);
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
        assert!(
            parse_request(&good[..cut]).is_err(),
            "cut at {cut} must fail"
        );
    }
}

#[test]
fn response_round_trips_with_digests() {
    let m = ResponseMessage {
        id: b"m-9".to_vec(),
        digest: integrity_digest(b"signed"),
        signed_pczt: b"signed".to_vec(),
    };
    let parsed = parse_response(&encode_response(std::slice::from_ref(&m), true).unwrap()).unwrap();
    assert_eq!(parsed, vec![m]);
}

// ── COMPACT signatures-only requests / responses ──────────────────────────

#[test]
fn compact_requests_parse_with_flag() {
    let req = SignRequest::Single(msg(b"", b"pczt-bytes"));
    let enc = encode_request_full(&req, true).unwrap();
    assert_eq!(enc[2], TX_TYPE_PCZT_SINGLE_COMPACT);
    let parsed = parse_request_full(&enc).unwrap();
    assert_eq!(parsed.request, req);
    assert!(parsed.compact);

    let batch = SignRequest::Batch(vec![msg(b"a", b"one"), msg(b"bb", b"two")]);
    let enc = encode_request_full(&batch, true).unwrap();
    assert_eq!(enc[2], TX_TYPE_PCZT_BATCH_COMPACT);
    let parsed = parse_request_full(&enc).unwrap();
    assert_eq!(parsed.request, batch);
    assert!(parsed.compact);

    // non-compact encoding keeps the old tx types and the old flag
    let parsed = parse_request_full(&encode_request(&req).unwrap()).unwrap();
    assert_eq!(parsed.request, req);
    assert!(!parsed.compact);
}

#[test]
fn compact_response_round_trips_single() {
    let m = CompactResponseMessage {
        id: Vec::new(),
        signatures: vec![
            SignatureContribution {
                pool: POOL_ORCHARD,
                action_index: 0,
                signature: [0xA1u8; 64],
            },
            SignatureContribution {
                pool: POOL_IRONWOOD,
                action_index: 3,
                signature: [0xB2; 64],
            },
        ],
    };
    let enc =
        encode_compact_response(std::slice::from_ref(&m), COMPACT_RESPONSE_VERSION, true).unwrap();
    assert_eq!(enc[2], TX_TYPE_PCZT_SINGLE_COMPACT_RESPONSE);
    let parsed = parse_compact_response(&enc).unwrap();
    assert_eq!(
        parsed,
        CompactResponse {
            version: COMPACT_RESPONSE_VERSION.to_string(),
            messages: vec![m],
        }
    );
}

#[test]
fn compact_response_round_trips_batch_and_echoes_ids() {
    let msgs = vec![
        CompactResponseMessage {
            id: b"m-1".to_vec(),
            signatures: vec![SignatureContribution {
                pool: POOL_ORCHARD,
                action_index: 0,
                signature: [0x11; 64],
            }],
        },
        CompactResponseMessage {
            id: b"m-2".to_vec(),
            signatures: vec![
                SignatureContribution {
                    pool: POOL_IRONWOOD,
                    action_index: 1,
                    signature: [0x22; 64],
                },
                SignatureContribution {
                    pool: POOL_ORCHARD,
                    action_index: 2,
                    signature: [0x33; 64],
                },
            ],
        },
    ];
    let enc = encode_compact_response(&msgs, "7", false).unwrap();
    assert_eq!(enc[2], TX_TYPE_PCZT_BATCH_COMPACT_RESPONSE);
    let parsed = parse_compact_response(&enc).unwrap();
    assert_eq!(
        parsed,
        CompactResponse {
            version: "7".to_string(),
            messages: msgs,
        }
    );
}

#[test]
fn compact_response_types_are_not_valid_requests() {
    // A device response must never be accepted back as a request: fail closed.
    for tx in [
        TX_TYPE_PCZT_SINGLE_COMPACT_RESPONSE,
        TX_TYPE_PCZT_BATCH_COMPACT_RESPONSE,
    ] {
        assert!(matches!(
            parse_request_full(&[PRELUDE, CRYPTO_TYPE_ZCASH, tx, 0, 0]).unwrap_err(),
            EnvelopeError::UnknownTxType(t)
                if t == tx
        ));
    }
}

#[test]
fn compact_response_rejects_unknown_pool() {
    let m = CompactResponseMessage {
        id: Vec::new(),
        signatures: vec![SignatureContribution {
            pool: 9,
            action_index: 0,
            signature: [0u8; 64],
        }],
    };
    assert!(encode_compact_response(&[m], "1", true).is_err());
}

#[test]
fn truncated_compact_response_fails() {
    let good = encode_compact_response(
        &[CompactResponseMessage {
            id: b"x".to_vec(),
            signatures: vec![SignatureContribution {
                pool: POOL_ORCHARD,
                action_index: 0,
                signature: [0u8; 64],
            }],
        }],
        "1",
        false,
    )
    .unwrap();
    for cut in 4..good.len() {
        assert!(
            parse_compact_response(&good[..cut]).is_err(),
            "compact cut at {cut} must fail"
        );
    }
}
