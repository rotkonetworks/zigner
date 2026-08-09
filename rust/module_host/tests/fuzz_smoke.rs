//! Deterministic mutation testing over the untrusted-input parsers.
//!
//! Not a substitute for cargo-fuzz (which needs nightly and should still be
//! run against these same entry points). This is the always-on half: it runs
//! on stable, in CI, on every commit, and its job is to ensure hostile bytes
//! produce an Err rather than a panic.
//!
//! Why these functions specifically: everything here parses bytes an attacker
//! controls, and two of them run BEFORE any signature has been checked.
//!
//! Round counts are deliberately modest: these run in the dev profile, where
//! ed25519 verification is orders of magnitude slower than release, and a
//! per-commit test that takes minutes gets disabled. Depth is cargo-fuzz's
//! job; breadth-on-every-commit is this file's.
//! `apply_patch` is reached through a payload that is never signed at all -
//! the manifest commits only to the RESULT hash - so bsdiff and ruzstd are
//! handed hostile input by design.

use ed25519_dalek::SigningKey;
use module_host::manifest::*;
use sha2::{Digest, Sha256};

/// xorshift64*, so failures are reproducible from the printed seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn keys() -> ([SigningKey; 3], [ed25519_dalek::VerifyingKey; 3]) {
    let sk = [
        SigningKey::from_bytes(&[1u8; 32]),
        SigningKey::from_bytes(&[2u8; 32]),
        SigningKey::from_bytes(&[3u8; 32]),
    ];
    let vk = [
        sk[0].verifying_key(),
        sk[1].verifying_key(),
        sk[2].verifying_key(),
    ];
    (sk, vk)
}

/// A well-formed package to mutate. Starting from valid input reaches far
/// deeper into the parsers than random bytes ever would.
fn seed_package() -> Vec<u8> {
    let (sk, _) = keys();
    let module = b"a module of some length to make the payload non-trivial".to_vec();
    build_package(
        &module,
        Sha256::digest(&module).into(),
        PAYLOAD_FULL,
        [0u8; 32],
        5,
        1,
        "changelog text",
        &[(0, sk[0].clone()), (2, sk[2].clone())],
    )
}

#[test]
fn mutated_packages_never_panic() {
    let (_, vk) = keys();
    let seed = seed_package();
    let base = b"some base module".to_vec();

    for round in 0..600u64 {
        let mut rng = Rng(round.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut p = seed.clone();

        // A handful of mutations: flip, truncate, extend, splice.
        for _ in 0..1 + rng.below(4) {
            if p.is_empty() {
                break;
            }
            match rng.below(4) {
                0 => {
                    let i = rng.below(p.len());
                    p[i] ^= 1u8 << rng.below(8);
                }
                1 => {
                    let i = rng.below(p.len());
                    p.truncate(i);
                }
                2 => {
                    let i = rng.below(p.len());
                    p[i] = rng.next() as u8;
                }
                _ => {
                    let n = rng.below(64);
                    for _ in 0..n {
                        p.push(rng.next() as u8);
                    }
                }
            }
        }

        // Any Ok/Err is fine. A panic is not - that is the whole assertion,
        // enforced by the harness rather than by a check we could forget.
        let _ = parse_signing_prefix(&p);
        let _ = verify_package(&p, &vk, 1, 0);
        let _ = verify_package_with_base(&p, &vk, 1, 0, Some(&base));
    }
}

/// The payload is NOT covered by the signatures, only its result hash is. So
/// a valid manifest paired with arbitrary payload bytes is a reachable state,
/// and the patch path must survive it.
#[test]
fn arbitrary_delta_payloads_never_panic() {
    let (sk, vk) = keys();
    let base = b"the base module, long enough to diff against".to_vec();

    for round in 0..60u64 {
        let mut rng = Rng(round.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
        let n = rng.below(512);
        let payload: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();

        let pkg = build_package(
            &payload,
            Sha256::digest(b"whatever the result should be").into(),
            PAYLOAD_BSDIFF_ZSTD,
            Sha256::digest(&base).into(),
            5,
            1,
            "delta",
            &[(0, sk[0].clone()), (2, sk[2].clone())],
        );
        let _ = verify_package_with_base(&pkg, &vk, 1, 0, Some(&base));
    }
}

/// A declared length that overflows a 32-bit usize must be an error, not a
/// reversed slice range. Green on 64-bit hosts by construction; the target it
/// actually protects is armeabi-v7a, which is a shipped ABI.
#[test]
fn absurd_declared_lengths_are_refused() {
    let (_, vk) = keys();
    for len in [u16::MAX, u16::MAX - 1, 0xFFFE, 0x8000] {
        let mut p = seed_package();
        // desc_len sits at magic(4) + ver(1) + mver(4) + mkver(4) + hash(32)
        // + kind(1) + base_hash(32) = 78.
        p[78..80].copy_from_slice(&len.to_le_bytes());
        let _ = parse_signing_prefix(&p);
        let _ = verify_package(&p, &vk, 1, 0);
    }
}
