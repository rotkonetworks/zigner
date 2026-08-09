//! Post-quantum HYBRID verifier for Zigner's update / anchor authority key.
//!
//! # Why
//!
//! Zigner is an air-gapped cold signer. The trust anchor for *cold updates*
//! (network specs, metadata, types) and for Zcash anchor attestation is a
//! single ed25519 publisher key (`constants::ROTKO_ZCASH_VERIFIER`, wired in
//! `defaults::default_general_verifier`). A future cryptographically-relevant
//! quantum computer would break ed25519 (Shor), letting an attacker forge a
//! signed update and push malicious metadata / a malicious signing request to
//! the device.
//!
//! Following Zcash's PQ guidance we use **ML-DSA (FIPS 204 / Dilithium)** for
//! signatures - NOT ML-KEM, which is a KEM for *encryption* only and must never
//! be used to authenticate. We combine it with the incumbent ed25519 in a
//! **belt-and-suspenders hybrid**: a hybrid signature carries BOTH an ed25519
//! signature AND an ML-DSA signature over the same message, and [`verify`]
//! accepts the update only if BOTH verify. A classical break (ed25519) OR a
//! quantum break (ML-DSA) *alone* is therefore insufficient to forge an update;
//! an attacker must break both. This also hedges implementation risk in the
//! young ML-DSA stack - a bug there cannot by itself downgrade security below
//! today's ed25519 baseline.
//!
//! [`verify`]: HybridPublicKey::verify
//!
//! # Parameter set
//!
//! **ML-DSA-65** (FIPS 204 category 3, ~192-bit classical / NIST L3). It is the
//! recommended balance of the three sets and matches Zcash ecosystem defaults.
//! Sizes (from the `ml-dsa` crate's own constants):
//!
//! | item              | ML-DSA-65 | ed25519 | hybrid total |
//! |-------------------|-----------|---------|--------------|
//! | public key        | 1952 B    | 32 B    | 1984 B       |
//! | signature         | 3309 B    | 64 B    | 3373 B       |
//!
//! # Crate choice
//!
//! We use the RustCrypto [`ml-dsa`](https://crates.io/crates/ml-dsa) crate
//! (v0.1.x), **not** `pqcrypto-dilithium`. Rationale:
//!
//! - **Pure Rust, no C toolchain.** `pqcrypto-dilithium` wraps the PQClean C
//!   reference via a `cc` build; that is painful for the wasm32 targets zigner
//!   already ships (`rust/zcash-wasm`) and for any future `no_std` embedded
//!   secure-element target. `ml-dsa` is `#![no_std]` with an `alloc`-free core
//!   and builds cleanly to wasm.
//! - **RustCrypto ecosystem fit.** It implements the `signature` traits, same
//!   family already pulled in transitively, and tracks FIPS 204 (ACVP-tested).
//! - **Honest caveat:** `ml-dsa` 0.1.x is pre-1.0 and explicitly *not yet
//!   independently audited*; the crate's own README says "USE AT YOUR OWN
//!   RISK". That is precisely why this is a *hybrid* - ed25519 remains the
//!   floor. Before production this dependency must be pinned to an audited
//!   release (or the verification vectors cross-checked against the NIST ACVP
//!   test vectors and a second implementation).
//!
//! # Status
//!
//! SCAFFOLD. The types and the dual-verify logic are real and tested against a
//! self-generated keypair, but nothing here is wired into the default build:
//! everything that touches ML-DSA is behind the `pq-hybrid` feature (OFF by
//! default). Production still needs: a real ML-DSA authority key generated on
//! an HSM, a wire-format/version bump for the QR payload prefix, and the
//! `MultiSigner`/`SufficientCrypto` integration on the `definitions` side.

#![forbid(unsafe_code)]

extern crate alloc;
use alloc::boxed::Box;

/// ML-DSA-65 encoded verifying-key length in bytes (FIPS 204, cat. 3).
pub const ML_DSA65_PUBLIC_LEN: usize = 1952;
/// ML-DSA-65 encoded signature length in bytes (FIPS 204, cat. 3).
pub const ML_DSA65_SIG_LEN: usize = 3309;
/// ed25519 public-key length in bytes.
pub const ED25519_PUBLIC_LEN: usize = 32;
/// ed25519 signature length in bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// Crypto-type prefix byte reserved for the hybrid scheme in the `53 xx yy`
/// Zigner update payload prelude (see `transaction_parsing`). `0x00` ed25519,
/// `0x01` sr25519, `0x02/0x03` ecdsa, `0x04` zcash and `0xff` unsigned are
/// already taken; `0x07` is free. This is a *proposed* allocation - it becomes
/// load-bearing only once the parser branch (below, feature-gated) ships.
pub const HYBRID_CRYPTO_PREFIX: u8 = 0x07;

/// A hybrid update-authority public key: classical ed25519 alongside
/// post-quantum ML-DSA-65. Both halves belong to the same authority and are
/// rotated together.
///
/// `ml_dsa` is boxed because a 1952-byte inline array would bloat every value
/// that embeds a verifier; the classical half stays inline for cheap display /
/// comparison and to keep the existing 32-byte ed25519 identity visible.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridPublicKey {
    /// ed25519 public key (32 bytes).
    pub ed25519: [u8; ED25519_PUBLIC_LEN],
    /// ML-DSA-65 encoded verifying key (1952 bytes).
    pub ml_dsa: Box<[u8]>,
}

/// A hybrid signature: `ed25519 || ML-DSA-65`, both over the *same* message.
///
/// On the wire this serialises as the fixed 64-byte ed25519 signature followed
/// by the fixed 3309-byte ML-DSA-65 signature (lengths are constants, so no
/// length prefix is needed between them).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridSignature {
    /// ed25519 signature (64 bytes).
    pub ed25519: [u8; ED25519_SIG_LEN],
    /// ML-DSA-65 signature (3309 bytes).
    pub ml_dsa: Box<[u8]>,
}

/// Reasons a hybrid verification can fail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HybridError {
    /// A field had the wrong byte length (malformed key or signature).
    BadLength,
    /// The classical (ed25519) signature did not verify.
    ClassicalFailed,
    /// The post-quantum (ML-DSA-65) signature did not verify.
    QuantumFailed,
    /// The `pq-hybrid` feature is not compiled in, so PQ verification is
    /// unavailable - fail closed rather than silently accept ed25519 alone.
    PqUnavailable,
}

impl HybridSignature {
    /// Total serialized length: ed25519 sig + ML-DSA-65 sig.
    pub const SERIALIZED_LEN: usize = ED25519_SIG_LEN + ML_DSA65_SIG_LEN;

    /// Parse a hybrid signature from the concatenated `ed25519 || ml_dsa` wire
    /// layout.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(HybridError::BadLength);
        }
        let mut ed25519 = [0u8; ED25519_SIG_LEN];
        ed25519.copy_from_slice(&bytes[..ED25519_SIG_LEN]);
        let ml_dsa = Box::from(&bytes[ED25519_SIG_LEN..]);
        Ok(Self { ed25519, ml_dsa })
    }

    /// Serialize to the `ed25519 || ml_dsa` wire layout.
    pub fn to_wire(&self) -> Box<[u8]> {
        let mut out = alloc::vec::Vec::with_capacity(Self::SERIALIZED_LEN);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.ml_dsa);
        out.into_boxed_slice()
    }
}

impl HybridPublicKey {
    /// Verify a [`HybridSignature`] over `msg`. Succeeds only if BOTH the
    /// ed25519 and the ML-DSA-65 signatures verify.
    ///
    /// Available only with the `pq-hybrid` feature. Without it, this returns
    /// [`HybridError::PqUnavailable`] so callers fail closed - they must fall
    /// back to the existing pure-ed25519 verifier path explicitly, never treat
    /// a hybrid payload as verified.
    #[cfg(feature = "pq-hybrid")]
    pub fn verify(&self, msg: &[u8], sig: &HybridSignature) -> Result<(), HybridError> {
        use ml_dsa::signature::Verifier as _;
        use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

        if self.ml_dsa.len() != ML_DSA65_PUBLIC_LEN || sig.ml_dsa.len() != ML_DSA65_SIG_LEN {
            return Err(HybridError::BadLength);
        }

        // 1. Classical half (ed25519). Use strict verification (rejects
        //    small-order / non-canonical points).
        let ed_vk = ed25519_dalek::VerifyingKey::from_bytes(&self.ed25519)
            .map_err(|_| HybridError::BadLength)?;
        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519);
        ed_vk
            .verify_strict(msg, &ed_sig)
            .map_err(|_| HybridError::ClassicalFailed)?;

        // 2. Post-quantum half (ML-DSA-65 / FIPS 204).
        let enc_vk = EncodedVerifyingKey::<MlDsa65>::try_from(self.ml_dsa.as_ref())
            .map_err(|_| HybridError::BadLength)?;
        let ml_vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
        let enc_sig = EncodedSignature::<MlDsa65>::try_from(sig.ml_dsa.as_ref())
            .map_err(|_| HybridError::BadLength)?;
        let ml_sig = Signature::<MlDsa65>::decode(&enc_sig).ok_or(HybridError::QuantumFailed)?;
        ml_vk
            .verify(msg, &ml_sig)
            .map_err(|_| HybridError::QuantumFailed)?;

        Ok(())
    }

    /// Feature-off stub: PQ verification is not compiled in.
    #[cfg(not(feature = "pq-hybrid"))]
    pub fn verify(&self, _msg: &[u8], _sig: &HybridSignature) -> Result<(), HybridError> {
        Err(HybridError::PqUnavailable)
    }
}

#[cfg(all(test, feature = "pq-hybrid"))]
mod tests {
    use super::*;
    use ml_dsa::{Generate as _, Keypair as _, MlDsa65, Signer as _, SigningKey};

    fn ed_keypair() -> ed25519_dalek::SigningKey {
        // Deterministic test key; NOT for production.
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn make_hybrid(msg: &[u8]) -> (HybridPublicKey, HybridSignature) {
        // ed25519
        let ed_sk = ed_keypair();
        let ed_pk = ed_sk.verifying_key();
        let ed_sig = {
            use ed25519_dalek::Signer;
            ed_sk.sign(msg)
        };
        // ML-DSA-65
        let ml_sk = SigningKey::<MlDsa65>::generate();
        let ml_vk = ml_sk.verifying_key();
        let ml_sig = ml_sk.sign(msg);

        let pk = HybridPublicKey {
            ed25519: ed_pk.to_bytes(),
            ml_dsa: ml_vk.encode().to_vec().into_boxed_slice(),
        };
        let sig = HybridSignature {
            ed25519: ed_sig.to_bytes(),
            ml_dsa: ml_sig.encode().to_vec().into_boxed_slice(),
        };
        (pk, sig)
    }

    #[test]
    fn both_valid_verifies() {
        let msg = b"zigner metadata update v1042";
        let (pk, sig) = make_hybrid(msg);
        assert_eq!(pk.ml_dsa.len(), ML_DSA65_PUBLIC_LEN);
        assert_eq!(sig.ml_dsa.len(), ML_DSA65_SIG_LEN);
        assert_eq!(pk.verify(msg, &sig), Ok(()));
    }

    #[test]
    fn wrong_message_fails() {
        let (pk, sig) = make_hybrid(b"good");
        assert!(pk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn broken_classical_half_fails_even_if_pq_ok() {
        let msg = b"belt and suspenders";
        let (mut pk, sig) = make_hybrid(msg);
        // Corrupt only the ed25519 public key; ML-DSA half still valid.
        pk.ed25519[0] ^= 0xff;
        assert!(matches!(
            pk.verify(msg, &sig),
            Err(HybridError::ClassicalFailed) | Err(HybridError::BadLength)
        ));
    }

    #[test]
    fn broken_pq_half_fails_even_if_classical_ok() {
        let msg = b"belt and suspenders";
        let (pk, mut sig) = make_hybrid(msg);
        // Corrupt the ML-DSA signature; ed25519 half still valid.
        let last = sig.ml_dsa.len() - 1;
        sig.ml_dsa[last] ^= 0xff;
        assert_eq!(pk.verify(msg, &sig), Err(HybridError::QuantumFailed));
    }

    #[test]
    fn wire_round_trip() {
        let (_pk, sig) = make_hybrid(b"x");
        let wire = sig.to_wire();
        assert_eq!(wire.len(), HybridSignature::SERIALIZED_LEN);
        assert_eq!(HybridSignature::from_wire(&wire).unwrap(), sig);
    }
}
