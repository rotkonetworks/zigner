//! End-to-end release ceremony against the real binary.
//!
//! The library path is covered in module_host; what is exercised here is the
//! CLI a release is actually driven from, split across machines the way custody
//! requires: prepare on the build host, two holders signing separately, then
//! assemble. No step ever sees two release keys.

use std::path::{Path, PathBuf};
use std::process::Command;

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn modpack_bin() -> PathBuf {
    // target/<profile>/deps/<test> -> target/<profile>/modpack
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("modpack")
}

fn run(dir: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(modpack_bin())
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run modpack");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

fn holder(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

/// Sign a prepared prefix the way a device does: over the domain-tagged
/// message the kernel reconstructs, never over caller-supplied bytes.
fn sign_as_holder(prefix: &[u8], n: u8) -> String {
    let msg = module_host::manifest::signing_message(prefix);
    hex::encode(holder(n).sign(&msg).to_bytes())
}

fn keyspecs() -> Vec<String> {
    (0u8..3)
        .map(|i| hex::encode(holder(i + 1).verifying_key().to_bytes()))
        .collect()
}

/// A module pair with enough shared structure for a delta to be worth taking -
/// the real asset is megabytes, which would make this test slow for no extra
/// signal.
fn module_pair() -> (Vec<u8>, Vec<u8>) {
    let base: Vec<u8> = (0..200_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let mut new = base.clone();
    for i in (1000..1200).step_by(7) {
        new[i] ^= 0xa5;
    }
    new.extend_from_slice(b"a handful of appended bytes");
    (base, new)
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("modpack-ceremony-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

#[test]
fn a_full_package_survives_the_three_machine_ceremony() {
    let d = tmpdir("full");
    let (_, module) = module_pair();
    std::fs::write(d.join("module.wasm"), &module).unwrap();
    std::fs::write(d.join("CHANGELOG"), "NU7: v6 transaction format").unwrap();

    let (ok, out) = run(
        &d,
        &[
            "prepare",
            "--module",
            "module.wasm",
            "--version",
            "3",
            "--changelog",
            "CHANGELOG",
        ],
    );
    assert!(ok, "prepare failed: {out}");

    let prefix = std::fs::read(d.join("prefix.bin")).expect("prepare wrote a prefix");

    // Two holders, signing independently. Neither process sees the other key.
    let s0 = sign_as_holder(&prefix, 1);
    let s2 = sign_as_holder(&prefix, 3);

    let (ok, out) = run(
        &d,
        &[
            "assemble",
            "--prefix",
            "prefix.bin",
            "--payload",
            "payload.bin",
            "--sig",
            &s0,
            "--sig",
            &s2,
            "--out",
            "package.zmod",
        ],
    );
    assert!(ok, "assemble failed: {out}");

    let keys = keyspecs();
    let (ok, out) = run(
        &d,
        &[
            "verify",
            "--package",
            "package.zmod",
            "--key",
            &keys[0],
            "--key",
            &keys[1],
            "--key",
            &keys[2],
        ],
    );
    assert!(ok, "verify failed: {out}");
    assert!(
        out.contains("NU7: v6 transaction format"),
        "verify must surface the signed changelog, got: {out}"
    );
}

#[test]
fn a_delta_package_rebuilds_the_module_and_is_far_smaller() {
    let d = tmpdir("delta");
    let (base, new) = module_pair();
    std::fs::write(d.join("base.wasm"), &base).unwrap();
    std::fs::write(d.join("module.wasm"), &new).unwrap();
    std::fs::write(d.join("CHANGELOG"), "delta release").unwrap();

    let (ok, out) = run(
        &d,
        &[
            "prepare",
            "--module",
            "module.wasm",
            "--base",
            "base.wasm",
            "--version",
            "4",
            "--changelog",
            "CHANGELOG",
        ],
    );
    assert!(ok, "prepare --base failed: {out}");

    let payload = std::fs::read(d.join("payload.bin")).unwrap();
    assert!(
        payload.len() < new.len() / 10,
        "a delta over a near-identical module should be tiny; got {} vs {}",
        payload.len(),
        new.len()
    );

    let prefix = std::fs::read(d.join("prefix.bin")).unwrap();
    let s0 = sign_as_holder(&prefix, 1);
    let s1 = sign_as_holder(&prefix, 2);
    let (ok, out) = run(
        &d,
        &[
            "assemble",
            "--prefix",
            "prefix.bin",
            "--payload",
            "payload.bin",
            "--sig",
            &s0,
            "--sig",
            &s1,
            "--out",
            "package.zmod",
        ],
    );
    assert!(ok, "assemble failed: {out}");

    // The kernel path: verify against the installed base and confirm the
    // module is reconstructed byte-exactly.
    let pkg = std::fs::read(d.join("package.zmod")).unwrap();
    let vks: [ed25519_dalek::VerifyingKey; 3] = [
        holder(1).verifying_key(),
        holder(2).verifying_key(),
        holder(3).verifying_key(),
    ];
    let verified = module_host::manifest::verify_package_with_base(&pkg, &vks, 1, 0, Some(&base))
        .expect("kernel must accept the assembled delta");
    assert_eq!(
        Sha256::digest(verified.module_bytes.as_ref()).as_slice(),
        Sha256::digest(&new).as_slice(),
        "the rebuilt module must be byte-identical to what was packed"
    );

    // And the CLI's own verify must refuse it without the base, rather than
    // pretending a delta is a whole module.
    let keys = keyspecs();
    let (ok, _) = run(
        &d,
        &[
            "verify",
            "--package",
            "package.zmod",
            "--key",
            &keys[0],
            "--key",
            &keys[1],
            "--key",
            &keys[2],
        ],
    );
    assert!(!ok, "verify must fail on a delta with no --base");
}

#[test]
fn assemble_refuses_one_signature_and_refuses_one_key_signing_twice() {
    let d = tmpdir("threshold");
    let (_, module) = module_pair();
    std::fs::write(d.join("module.wasm"), &module).unwrap();
    std::fs::write(d.join("CHANGELOG"), "threshold test").unwrap();
    let (ok, out) = run(
        &d,
        &[
            "prepare",
            "--module",
            "module.wasm",
            "--version",
            "2",
            "--changelog",
            "CHANGELOG",
        ],
    );
    assert!(ok, "prepare failed: {out}");
    let prefix = std::fs::read(d.join("prefix.bin")).unwrap();

    let s0 = sign_as_holder(&prefix, 1);
    let (ok, out) = run(
        &d,
        &[
            "assemble",
            "--prefix",
            "prefix.bin",
            "--payload",
            "payload.bin",
            "--sig",
            &s0,
            "--out",
            "one.zmod",
        ],
    );
    assert!(!ok, "one signature is not 2-of-3");
    assert!(
        out.to_lowercase().contains("2") || out.to_lowercase().contains("signature"),
        "{out}"
    );

    // Same holder twice is not two holders.
    let (ok, out) = run(
        &d,
        &[
            "assemble",
            "--prefix",
            "prefix.bin",
            "--payload",
            "payload.bin",
            "--sig",
            &s0,
            "--sig",
            &s0,
            "--out",
            "dup.zmod",
        ],
    );
    assert!(!ok, "a duplicate signature must be refused: {out}");
}

/// The changelog is not optional, and that is a security property rather than
/// a nicety: it sits inside the signed region and is what the user reads on
/// the confirm screen before approving. A release that could omit it would be
/// a release the user has to approve blind.
#[test]
fn prepare_refuses_a_release_with_no_changelog() {
    let d = tmpdir("nochangelog");
    let (_, module) = module_pair();
    std::fs::write(d.join("module.wasm"), &module).unwrap();
    let (ok, out) = run(
        &d,
        &["prepare", "--module", "module.wasm", "--version", "2"],
    );
    assert!(!ok, "prepare must require a changelog");
    assert!(out.contains("changelog"), "unhelpful refusal: {out}");
}
