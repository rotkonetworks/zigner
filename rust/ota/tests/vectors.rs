//! Golden-corpus tests for the Zafu/Zigner firmware OTA wire contract.
//!
//! Reads rust/ota/test-data/test-vectors.json (identical to the zafu corpus)
//! and asserts the device-side implementation matches byte-for-byte.

use ota::semver;
use ota::stream::verify_stream;
use ota::types::{
    decode_result, decode_status, image_canonical, manifest_signed_canonical,
    result_signed_canonical, result_wire_canonical, status_signed_canonical, status_wire_canonical,
    ImageHeader, Manifest, OtaResult, Status, TAG_IMAGE, TAG_MANIFEST, TAG_RESULT, TAG_STATUS,
};
use ota::verifysig::{verify_image, verify_manifest, verify_result, verify_status};
use serde_json::Value;

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}
fn hex64(s: &str) -> [u8; 64] {
    hex::decode(s).unwrap().try_into().unwrap()
}
fn hex8(s: &str) -> [u8; 8] {
    hex::decode(s).unwrap().try_into().unwrap()
}
fn a32(v: &[u8]) -> [u8; 32] {
    v.try_into().unwrap()
}
fn a64(v: &[u8]) -> [u8; 64] {
    v.try_into().unwrap()
}

struct Corpus {
    root: Value,
}
impl Corpus {
    fn load() -> Self {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/test-data/test-vectors.json");
        Corpus {
            root: ota::corpus::load(p).expect("parse corpus"),
        }
    }
    fn pinned(&self) -> [u8; 32] {
        hex32(self.root["ota_sign_public_key_hex"].as_str().unwrap())
    }
    fn board(&self) -> &str {
        self.root["board"].as_str().unwrap()
    }
    fn payload(&self) -> Vec<u8> {
        hex::decode(self.root["payload_bytes"].as_str().unwrap()).unwrap()
    }
    fn vec(&self, name: &str) -> &Value {
        &self.root["vectors"][name]
    }
}

/// Signed-field view of a manifest/image vector.
struct SignVec {
    version: String,
    min_version: String,
    key_id: u64,
    class: String,
    payload_size: u64,
    payload_sha256: Vec<u8>,
    manifest_canonical: Vec<u8>,
    manifest_signed: Vec<u8>,
    manifest_sig: Vec<u8>,
    image_canonical: Vec<u8>,
    image_signed: Vec<u8>,
    image_sig: Vec<u8>,
    req_id: Vec<u8>,
}

impl Corpus {
    fn sign_vectors(&self, name: &str) -> SignVec {
        let v = self.vec(name);
        let gh = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
        SignVec {
            version: v["version"].as_str().unwrap().to_string(),
            min_version: v["min_version"].as_str().unwrap().to_string(),
            key_id: v["key_id"].as_u64().unwrap(),
            class: v["class"].as_str().unwrap().to_string(),
            payload_size: v["payload_size"].as_u64().unwrap(),
            payload_sha256: gh("payload_sha256_hex"),
            manifest_canonical: gh("manifest_canonical_hex"),
            manifest_signed: gh("manifest_signed_hex"),
            manifest_sig: gh("manifest_sig_hex"),
            image_canonical: gh("image_canonical_hex"),
            image_signed: gh("image_signed_hex"),
            image_sig: gh("image_sig_hex"),
            req_id: v
                .get("req_id_hex")
                .map(|r| hex::decode(r.as_str().unwrap()).unwrap())
                .unwrap_or_default(),
        }
    }
}

fn manifest_from(v: &SignVec, c: &Corpus) -> Manifest {
    Manifest {
        version: v.version.clone(),
        board: c.board().to_string(),
        payload_sha256: a32(&v.payload_sha256),
        payload_size: v.payload_size,
        min_version: v.min_version.clone(),
        key_id: v.key_id,
        class: v.class.clone(),
        image_sig: None,
        req_id: None,
    }
}
fn image_header_from(v: &SignVec, c: &Corpus) -> ImageHeader {
    ImageHeader {
        key_id: v.key_id,
        board: c.board().to_string(),
        version: v.version.clone(),
        payload_sha256: a32(&v.payload_sha256),
        payload_len: v.payload_size,
    }
}

/// Build a full `ur:zafu-stream` buffer (manifest frame0 || image wrapper).
fn build_stream(v: &SignVec, payload: &[u8], m: &Manifest, req_id: [u8; 8]) -> Vec<u8> {
    // Prefer the manifest's own image_sig (so tampering tests can inject a
    // bad one), falling back to the corpus value.
    let isig: [u8; 64] = m.image_sig.unwrap_or_else(|| a64(&v.image_sig));
    let mut buf = ota::types::manifest_frame0_canonical(m, &isig, &req_id).unwrap();
    buf.extend_from_slice(&(v.key_id as u32).to_le_bytes());
    buf.extend_from_slice(&(v.payload_size as u32).to_le_bytes());
    buf.extend_from_slice(&v.payload_sha256);
    buf.extend_from_slice(payload);
    buf
}

/// Full wire-frame manifest (image_sig + req_id populated).
fn base_manifest(v: &SignVec, c: &Corpus) -> Manifest {
    let mut m = manifest_from(v, c);
    m.image_sig = Some(a64(&v.image_sig));
    if !v.req_id.is_empty() {
        m.req_id = Some(a8(&v.req_id));
    }
    m
}
fn a8(v: &[u8]) -> [u8; 8] {
    v.try_into().unwrap()
}

#[test]
fn corpus_manifest_encode_matches_byte_for_byte() {
    let c = Corpus::load();
    for name in ["release_0_9_0", "rollback_0_8_5"] {
        let v = c.sign_vectors(name);
        let m = manifest_from(&v, &c);
        assert_eq!(
            manifest_signed_canonical(&m).unwrap(),
            v.manifest_canonical,
            "{name} manifest canonical"
        );
        let mut expected = TAG_MANIFEST.to_vec();
        expected.extend_from_slice(&v.manifest_canonical);
        assert_eq!(expected, v.manifest_signed, "{name} manifest signed");
    }
}

#[test]
fn corpus_image_encode_matches_byte_for_byte() {
    let c = Corpus::load();
    for name in ["release_0_9_0", "rollback_0_8_5"] {
        let v = c.sign_vectors(name);
        let h = image_header_from(&v, &c);
        assert_eq!(
            image_canonical(&h).unwrap(),
            v.image_canonical,
            "{name} image canonical"
        );
        let mut expected = TAG_IMAGE.to_vec();
        expected.extend_from_slice(&v.image_canonical);
        assert_eq!(expected, v.image_signed, "{name} image signed");
    }
}

#[test]
fn corpus_signatures_verify_positive() {
    let c = Corpus::load();
    let pinned = c.pinned();
    for name in ["release_0_9_0", "rollback_0_8_5"] {
        let v = c.sign_vectors(name);
        let m = manifest_from(&v, &c);
        verify_manifest(&m, &a64(&v.manifest_sig), &pinned)
            .unwrap_or_else(|e| panic!("{name} manifest verify: {e}"));
        let h = image_header_from(&v, &c);
        verify_image(&h, &a64(&v.image_sig), &pinned)
            .unwrap_or_else(|e| panic!("{name} image verify: {e}"));
    }
}

#[test]
fn corpus_result_matches_and_verifies() {
    let c = Corpus::load();
    let rv = c.vec("result_success_B");
    let canonical = hex::decode(rv["canonical_hex"].as_str().unwrap()).unwrap();
    let signed = hex::decode(rv["signed_hex"].as_str().unwrap()).unwrap();
    let result_sig = hex64(rv["result_sig_hex"].as_str().unwrap());

    let r = OtaResult {
        fw_version: rv["fw_version"].as_str().unwrap().to_string(),
        success: rv["success"].as_bool().unwrap(),
        slot: rv["slot"].as_str().unwrap().as_bytes()[0],
        req_id: hex8(rv["req_id_hex"].as_str().unwrap()),
        zid_pubkey: hex32(rv["zid_pubkey_hex"].as_str().unwrap()),
        result_sig,
    };
    assert_eq!(
        result_signed_canonical(&r).unwrap(),
        canonical,
        "result canonical"
    );
    let mut expected = TAG_RESULT.to_vec();
    expected.extend_from_slice(&canonical);
    assert_eq!(expected, signed, "result signed");
    verify_result(&r).unwrap();

    let wire = result_wire_canonical(&r).unwrap();
    let decoded = decode_result(&wire).unwrap();
    assert_eq!(decoded.result_sig, result_sig);
    verify_result(&decoded).unwrap();
}

#[test]
fn corpus_status_matches_and_verifies() {
    let c = Corpus::load();
    let sv = c.vec("status");
    let canonical = hex::decode(sv["canonical_hex"].as_str().unwrap()).unwrap();
    let signed = hex::decode(sv["signed_hex"].as_str().unwrap()).unwrap();

    let s = Status {
        fw_version: sv["fw_version"].as_str().unwrap().to_string(),
        slot: sv["slot"].as_str().unwrap().as_bytes()[0],
        successful_boot: sv["successful_boot"].as_bool().unwrap(),
        zid_pubkey: hex32(sv["zid_pubkey_hex"].as_str().unwrap()),
        status_sig: hex64(sv["status_sig_hex"].as_str().unwrap()),
    };
    assert_eq!(
        status_signed_canonical(&s).unwrap(),
        canonical,
        "status canonical"
    );
    let mut expected = TAG_STATUS.to_vec();
    expected.extend_from_slice(&canonical);
    assert_eq!(expected, signed, "status signed");
    verify_status(&s).unwrap();

    let wire = status_wire_canonical(&s).unwrap();
    let decoded = decode_status(&wire).unwrap();
    verify_status(&decoded).unwrap();
}

#[test]
fn semver_corpus_matrix() {
    for (a, b) in [
        ("0.8.5", "0.8.5"),
        ("0.8.5", "0.8.10"),
        ("0.9.0", "0.8.5"),
        ("1.0.0", "0.99.99"),
        ("1.2.3", "1.2.2"),
        ("1.2.3", "1.3.0"),
    ] {
        let got = semver::compare(a, b).expect("valid semver");
        let expected = golden_tuple(a).cmp(&golden_tuple(b));
        assert_eq!(got, expected, "compare {a} vs {b}");
    }
}

fn golden_tuple(s: &str) -> (u64, u64, u64) {
    let mut it = s.split('.');
    (
        it.next().unwrap().parse().unwrap(),
        it.next().unwrap().parse().unwrap(),
        it.next().unwrap().parse().unwrap(),
    )
}

#[test]
fn semver_rejects_bad_versions() {
    for bad in [
        "v0.9.0",
        "V1.2.3",
        "0.9",
        "0.9.0-beta",
        "0.9.0+build",
        "0.a.0",
        "..",
        "0.9.0.1",
        "",
        " 0.9.0",
    ] {
        assert!(semver::parse(bad).is_none(), "should reject {bad:?}");
    }
}

#[test]
fn corpus_verify_stream_end_to_end() {
    let c = Corpus::load();
    let v = c.sign_vectors("release_0_9_0");
    let pinned = c.pinned();
    let payload = c.payload();
    let req_id = a8(&v.req_id);
    let m = base_manifest(&v, &c);
    let buf = build_stream(&v, &payload, &m, req_id);
    let msig = a64(&v.manifest_sig);

    let vs = verify_stream(&buf, &msig, &pinned, "0.8.0", c.board(), &[], false)
        .expect("release stream verifies");
    assert_eq!(vs.manifest.version, "0.9.0");
    assert_eq!(vs.payload_sha256, a32(&v.payload_sha256));
    assert_eq!(vs.payload_len, v.payload_size);
}

#[test]
fn corpus_rejections() {
    let c = Corpus::load();
    let pinned = c.pinned();
    let payload = c.payload();
    let v = c.sign_vectors("release_0_9_0");
    let req_id = a8(&v.req_id);
    let msig = a64(&v.manifest_sig);

    let m = base_manifest(&v, &c);
    let good = build_stream(&v, &payload, &m, req_id);

    // Sanity: valid stream passes.
    assert!(verify_stream(&good, &msig, &pinned, "0.8.0", c.board(), &[], false).is_ok());

    // Wrong pinned key.
    let wrong = [0xAAu8; 32];
    assert!(verify_stream(&good, &msig, &wrong, "0.8.0", c.board(), &[], false).is_err());

    // Tampered image_sig.
    let mut bad_sig = v.image_sig.clone();
    bad_sig[0] ^= 0xff;
    let mut m2 = m.clone();
    m2.image_sig = Some(a64(&bad_sig));
    let tampered = build_stream(&v, &payload, &m2, req_id);
    assert!(verify_stream(&tampered, &msig, &pinned, "0.8.0", c.board(), &[], false).is_err());

    // Blacklisted key_id.
    assert!(verify_stream(
        &good,
        &msig,
        &pinned,
        "0.8.0",
        c.board(),
        &[v.key_id],
        false
    )
    .is_err());

    // Wrong board.
    assert!(verify_stream(
        &good,
        &msig,
        &pinned,
        "0.8.0",
        "some-other-board",
        &[],
        false
    )
    .is_err());

    // Bad class (unknown) — repackaged with a bogus class; either the
    // signature or the class gate must reject it.
    let mut m3 = m.clone();
    m3.class = "beta".to_string();
    let repackaged = build_stream(&v, &payload, &m3, req_id);
    assert!(verify_stream(&repackaged, &msig, &pinned, "0.8.0", c.board(), &[], false).is_err());

    // Rollback class not applicable on the wire.
    let rv = c.sign_vectors("rollback_0_8_5");
    let rm = base_manifest(&rv, &c);
    let rbuf = build_stream(&rv, &payload, &rm, req_id);
    let rmsig = a64(&rv.manifest_sig);
    assert!(verify_stream(&rbuf, &rmsig, &pinned, "0.8.0", c.board(), &[], false).is_err());

    // Downgrade: version <= current.
    assert!(verify_stream(&good, &msig, &pinned, "0.9.0", c.board(), &[], false).is_err());

    // Below min_version.
    let mut m4 = m.clone();
    m4.min_version = "9.9.9".to_string();
    let below = build_stream(&v, &payload, &m4, req_id);
    assert!(verify_stream(&below, &msig, &pinned, "0.8.0", c.board(), &[], false).is_err());
}

#[test]
fn strict_cbor_rejects_trailing_and_nonminimal() {
    let ok = [0xa1, 0x01, 0x00];
    assert!(ota::decode(&ok).is_ok());
    assert!(ota::decode(&[0xa1, 0x01, 0x00, 0x00]).is_err());
    assert!(ota::decode(&[0xa1, 0x01, 0x18, 0x05]).is_err());
    assert!(ota::decode(&[0xbf, 0x01, 0x00, 0xff]).is_err());
}

#[test]
fn produce_result_and_status_round_trip() {
    // Produce a result with a known secret, decode it, verify the sig.
    let sk: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
    let req = *b"\x01\x02\x03\x04\x05\x06\x07\x08";
    let wire = ota::result::produce_result("0.9.0", true, b'B', &req, &sk).unwrap();
    let r = decode_result(&wire).unwrap();
    verify_result(&r).unwrap();
    assert_eq!(r.fw_version, "0.9.0");
    assert!(r.success);
    assert_eq!(r.slot, b'B');
    assert_eq!(r.req_id, req);
    assert_eq!(r.zid_pubkey, ota::result::zid_public_key(&sk));

    let swire = ota::result::produce_status("0.9.0", b'A', true, &sk).unwrap();
    let s = decode_status(&swire).unwrap();
    verify_status(&s).unwrap();
    assert_eq!(s.slot, b'A');
    assert!(s.successful_boot);
}
