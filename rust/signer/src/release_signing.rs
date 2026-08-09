// release_signing.rs — the device as a release-signing key holder.
//
// Three zigner devices, three seeds, three release keys: that is the 2-of-3
// set baked into the kernel as RELEASE_KEY_BYTES. Each holder signs a module
// manifest offline, over QR, and never sees the other two keys. The asymmetry
// with `module_host::manifest::build_package` is deliberate - that helper takes
// every signing key at once and so requires them all on one machine, which is
// exactly what the custody model forbids. It stays a test helper; this is the
// real path.
//
// The invariant that makes this safe is small and worth stating plainly:
//
//   THE DEVICE PREPENDS THE DOMAIN ITSELF.
//
// The host sends only the manifest's signed region. The device parses it,
// shows the operator what it says, and constructs "zigner-module-v1" || prefix
// locally. A host that wanted a signature over something else would have to
// smuggle it through a parser that only accepts well-formed manifests - so a
// release key cannot be turned into a general signing oracle by whatever is
// driving the QR on the other side.

use sp_core::Pair;

use crate::auth::derive_domain_keypair;
use module_host::manifest::{self, ManifestFields};

/// Derivation domain for release-signing keys. Distinct from the SSH and
/// auth-identity domains: one seed may serve several roles, but a signature
/// made for one role must never be valid in another.
pub const RELEASE_DOMAIN: &str = "zigner-release";

/// What this device is being asked to attest to, for display before approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSigningRequest {
    pub module_version: u32,
    pub min_kernel_version: u32,
    /// Full sha256 of the module. The operator is attesting that THIS hash is
    /// the build they verified - the device cannot check that for them, so the
    /// UI must show it and the signer must have a reproducible build to
    /// compare against. Without that, the signature is ceremony.
    pub module_hash_hex: String,
    pub description: String,
}

impl From<ManifestFields> for ReleaseSigningRequest {
    fn from(f: ManifestFields) -> Self {
        Self {
            module_version: f.module_version,
            min_kernel_version: f.min_kernel_version,
            module_hash_hex: hex::encode(f.module_hash),
            description: f.description,
        }
    }
}

/// This device's release public key, hex, for baking into `RELEASE_KEY_BYTES`.
pub fn public_key_hex(seed_phrase: &str, index: u32) -> Result<String, String> {
    let pair = derive_domain_keypair(seed_phrase, RELEASE_DOMAIN, index)?;
    Ok(hex::encode(pair.public().0))
}

/// Parse a scanned manifest prefix for display, or refuse it.
pub fn classify_request(prefix: &[u8]) -> Result<ReleaseSigningRequest, String> {
    let (fields, consumed) = manifest::parse_signing_prefix(prefix)
        .map_err(|e| format!("not a module manifest: {e:?}"))?;
    // The prefix must be exactly the signed region - no more. Trailing bytes
    // would mean we are displaying one thing and signing another.
    if consumed != prefix.len() {
        return Err(format!(
            "trailing bytes after the manifest: signed region is {} bytes, got {}",
            consumed,
            prefix.len()
        ));
    }
    Ok(fields.into())
}

/// Sign a module manifest prefix with this device's release key.
///
/// Returns `(public_key_hex, signature_hex)`. The signature is over
/// `"zigner-module-v1" || prefix`, constructed here rather than accepted from
/// the caller. Caller is expected to have displayed [`classify_request`] and
/// obtained approval; this function is not itself consent.
pub fn sign_request(
    seed_phrase: &str,
    index: u32,
    prefix: &[u8],
) -> Result<(String, String), String> {
    // Parse before signing, always.
    let _ = classify_request(prefix)?;

    let mut message = Vec::with_capacity(manifest::DOMAIN.len() + prefix.len());
    message.extend_from_slice(manifest::DOMAIN);
    message.extend_from_slice(prefix);

    let pair = derive_domain_keypair(seed_phrase, RELEASE_DOMAIN, index)?;
    let signature = pair.sign(&message);
    Ok((hex::encode(pair.public().0), hex::encode(signature.0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;
    use sha2::{Digest, Sha256};
    use std::convert::TryInto;

    const SEED_A: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
    const SEED_B: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const SEED_C: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

    /// Build the signed region the way the packer would.
    fn prefix(module: &[u8], version: u32, desc: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(manifest::MAGIC);
        out.push(1);
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&Sha256::digest(module));
        out.extend_from_slice(&(desc.len() as u16).to_le_bytes());
        out.extend_from_slice(desc.as_bytes());
        out
    }

    fn verifying_key(seed: &str) -> VerifyingKey {
        let hexed = public_key_hex(seed, 0).unwrap();
        let raw: [u8; 32] = hex::decode(hexed).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&raw).unwrap()
    }

    #[test]
    fn release_keys_are_separate_from_ssh_and_identity() {
        let release = public_key_hex(SEED_A, 0).unwrap();
        let identity = crate::auth::derive_identity(SEED_A, 0).unwrap();
        let ssh = crate::auth::derive_domain_identity(SEED_A, crate::ssh::SSH_DOMAIN, 0).unwrap();
        assert_ne!(release, identity);
        assert_ne!(release, ssh);
    }

    #[test]
    fn distinct_seeds_give_distinct_release_keys() {
        // Three holders must be three keys, or 2-of-3 is theatre.
        let a = public_key_hex(SEED_A, 0).unwrap();
        let b = public_key_hex(SEED_B, 0).unwrap();
        let c = public_key_hex(SEED_C, 0).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn classify_surfaces_the_fields_the_operator_must_check() {
        let module = b"wasm bytes";
        let req = classify_request(&prefix(module, 7, "fixes the thing")).unwrap();
        assert_eq!(req.module_version, 7);
        assert_eq!(req.description, "fixes the thing");
        assert_eq!(req.module_hash_hex, hex::encode(Sha256::digest(module)));
    }

    #[test]
    fn refuses_anything_that_is_not_a_manifest() {
        for junk in [
            b"SSHSIG\x00\x00\x00\x03git".to_vec(),
            b"not a manifest at all".to_vec(),
            Vec::new(),
            vec![0xff; 60],
        ] {
            assert!(
                sign_request(SEED_A, 0, &junk).is_err(),
                "signed a non-manifest payload"
            );
        }
    }

    #[test]
    fn refuses_trailing_bytes_after_the_signed_region() {
        // A prefix with extra bytes appended would be displayed as the short
        // version while a longer message got signed.
        let mut p = prefix(b"wasm", 1, "ok");
        p.extend_from_slice(b"and something else");
        assert!(sign_request(SEED_A, 0, &p).is_err());
    }

    /// The load-bearing test: signatures produced on-device by sp_core must
    /// verify in the real kernel verifier, which uses ed25519-dalek's strict
    /// equation. Two different libraries, one wire format.
    #[test]
    fn two_devices_produce_a_package_the_kernel_accepts() {
        let module = b"the module bytes";
        let p = prefix(module, 3, "changelog the user will read on the device");

        // Holder A (key index 0) and holder C (key index 2) sign, separately.
        let (_, sig_a) = sign_request(SEED_A, 0, &p).unwrap();
        let (_, sig_c) = sign_request(SEED_C, 0, &p).unwrap();

        let mut package = p.clone();
        package.push(2); // sig_count
        package.push(0);
        package.extend_from_slice(&hex::decode(sig_a).unwrap());
        package.push(2);
        package.extend_from_slice(&hex::decode(sig_c).unwrap());
        package.extend_from_slice(module);

        let keys = [
            verifying_key(SEED_A),
            verifying_key(SEED_B),
            verifying_key(SEED_C),
        ];
        let verified = manifest::verify_package(&package, &keys, 1, 0)
            .expect("kernel must accept two device-made signatures");
        assert_eq!(verified.module_version, 3);
        assert_eq!(
            verified.description,
            "changelog the user will read on the device"
        );
        assert_eq!(verified.module_bytes, module);
    }

    #[test]
    fn one_signature_is_not_enough() {
        let module = b"the module bytes";
        let p = prefix(module, 3, "x");
        let (_, sig_a) = sign_request(SEED_A, 0, &p).unwrap();

        let mut package = p.clone();
        package.push(1);
        package.push(0);
        package.extend_from_slice(&hex::decode(sig_a).unwrap());
        package.extend_from_slice(module);

        let keys = [
            verifying_key(SEED_A),
            verifying_key(SEED_B),
            verifying_key(SEED_C),
        ];
        assert!(manifest::verify_package(&package, &keys, 1, 0).is_err());
    }

    /// A signature made under the SSH domain must be worthless as a release
    /// signature. This is the concrete payoff of domain separation.
    #[test]
    fn an_ssh_domain_signature_cannot_pass_as_a_release_signature() {
        let module = b"the module bytes";
        let p = prefix(module, 3, "x");

        let mut message = Vec::from(manifest::DOMAIN);
        message.extend_from_slice(&p);
        let ssh_pair = derive_domain_keypair(SEED_A, crate::ssh::SSH_DOMAIN, 0).unwrap();
        let rogue = ssh_pair.sign(&message);

        let (_, sig_c) = sign_request(SEED_C, 0, &p).unwrap();
        let mut package = p.clone();
        package.push(2);
        package.push(0);
        package.extend_from_slice(&rogue.0);
        package.push(2);
        package.extend_from_slice(&hex::decode(sig_c).unwrap());
        package.extend_from_slice(module);

        let keys = [
            verifying_key(SEED_A),
            verifying_key(SEED_B),
            verifying_key(SEED_C),
        ];
        assert!(
            manifest::verify_package(&package, &keys, 1, 0).is_err(),
            "an SSH-domain signature must not satisfy a release key slot"
        );
    }
}
