// ssh.rs — SSH signing over the airgap.
//
// The device holds an ed25519 key derived under its own domain and signs SSH
// payloads scanned in as QR. The counterpart on the host is an ssh-agent, not
// a patched ssh client: OpenSSH already exposes the agent protocol, so `ssh`,
// `scp`, `git` and `ssh-keygen -Y sign` all work unmodified against it.
//
// Two properties this file is responsible for:
//
//  1. DOMAIN SEPARATION. The SSH key is derived under SSH_DOMAIN, distinct
//     from the release-signing and auth-identity domains. A signature made
//     here can never be valid as a release manifest signature, because it is
//     made with a different key entirely.
//
//  2. NO GENERIC SIGNING ORACLE. `classify_request` parses the payload into a
//     known SSH framing and everything else is refused. Without this, an agent
//     that will sign arbitrary bytes is a machine for producing signatures
//     over structures we never inspected. Refusing unknown framing is what
//     keeps "the device signs SSH things" from becoming "the device signs".

use sp_core::Pair;
use std::convert::TryInto;

use crate::auth::derive_domain_keypair;

/// Derivation domain for SSH keys. Distinct from the release domain so that
/// compromise of one authority does not imply the other.
pub const SSH_DOMAIN: &str = "zigner-ssh";

/// The only public-key algorithm this surface speaks.
const ALG: &str = "ssh-ed25519";

/// SSHSIG blobs (`ssh-keygen -Y sign`, git commit signing) open with this
/// literal, unprefixed. Its absence is what distinguishes a userauth blob.
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// RFC 4252 section 7.
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// A signing payload we understood well enough to show a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshSignRequest {
    /// Interactive authentication. Note what is NOT here: the hostname. The
    /// signed blob does not carry one - the session identifier binds the
    /// server's host key, so a signature cannot be replayed to a different
    /// server, but it cannot be inverted to display where the login is going.
    /// The confirm screen must not imply otherwise.
    UserAuth { username: String, service: String },
    /// A detached signature over a document - `ssh-keygen -Y sign`, which is
    /// also what git drives for signed commits and tags. The namespace ("git",
    /// "file", ...) and the message hash are displayable.
    SshSig {
        namespace: String,
        hash_algorithm: String,
        message_hash_hex: String,
    },
}

// ── SSH wire primitives (RFC 4251 section 5) ────────────────────────────────

/// Encode a length-prefixed SSH string.
fn ssh_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Read a length-prefixed SSH string, returning it and the remainder.
fn take_string(b: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if b.len() < 4 {
        return Err("truncated: expected a length-prefixed string".into());
    }
    let len = u32::from_be_bytes(b[0..4].try_into().unwrap()) as usize;
    // checked_add, not `4 + len`. armeabi-v7a is a shipped ABI and its usize
    // is 32-bit, so a declared length near u32::MAX wraps: `4 + len` becomes
    // a small number, the bounds check below passes, and the slice is then
    // built with end < start - a panic on hostile input, on a real target.
    // Release builds wrap silently, so nothing would have caught it earlier.
    let end = 4usize
        .checked_add(len)
        .ok_or_else(|| format!("string length {len} overflows this platform's address size"))?;
    if b.len() < end {
        return Err(format!(
            "truncated: string claims {} bytes, {} remain",
            len,
            b.len() - 4
        ));
    }
    Ok((&b[4..end], &b[end..]))
}

fn take_utf8(b: &[u8]) -> Result<(String, &[u8]), String> {
    let (s, rest) = take_string(b)?;
    let s = std::str::from_utf8(s).map_err(|_| "non-utf8 where text expected".to_string())?;
    Ok((s.to_string(), rest))
}

/// The `ssh-ed25519` public key blob: `string "ssh-ed25519" || string key`.
pub fn public_key_blob(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = ssh_string(ALG.as_bytes());
    out.extend_from_slice(&ssh_string(pubkey));
    out
}

// ── public surface ──────────────────────────────────────────────────────────

/// Derive the SSH public key as an `authorized_keys` line.
pub fn public_key_line(seed_phrase: &str, index: u32, comment: &str) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let pair = derive_domain_keypair(seed_phrase, SSH_DOMAIN, index)?;
    let blob = STANDARD.encode(public_key_blob(&pair.public().0));
    Ok(if comment.is_empty() {
        format!("{ALG} {blob}")
    } else {
        format!("{ALG} {blob} {comment}")
    })
}

/// Parse a signing payload into a framing we can display, or refuse it.
pub fn classify_request(blob: &[u8]) -> Result<SshSignRequest, String> {
    if blob.starts_with(SSHSIG_MAGIC) {
        return classify_sshsig(&blob[SSHSIG_MAGIC.len()..]);
    }
    classify_userauth(blob)
}

fn classify_sshsig(rest: &[u8]) -> Result<SshSignRequest, String> {
    let (namespace, rest) = take_utf8(rest)?;
    let (_reserved, rest) = take_string(rest)?;
    let (hash_algorithm, rest) = take_utf8(rest)?;
    let (message_hash, rest) = take_string(rest)?;
    if !rest.is_empty() {
        return Err("trailing bytes after SSHSIG structure".into());
    }
    if namespace.is_empty() {
        return Err("SSHSIG namespace is empty".into());
    }
    Ok(SshSignRequest::SshSig {
        namespace,
        hash_algorithm,
        message_hash_hex: hex::encode(message_hash),
    })
}

fn classify_userauth(blob: &[u8]) -> Result<SshSignRequest, String> {
    let (session_id, rest) = take_string(blob)?;
    if session_id.is_empty() {
        return Err("userauth blob has an empty session identifier".into());
    }
    let (&msg_type, rest) = rest
        .split_first()
        .ok_or_else(|| "truncated: expected a message type".to_string())?;
    if msg_type != SSH_MSG_USERAUTH_REQUEST {
        return Err(format!(
            "unrecognised payload: not an SSH userauth request (message type {msg_type})"
        ));
    }
    let (username, rest) = take_utf8(rest)?;
    let (service, rest) = take_utf8(rest)?;
    let (method, rest) = take_utf8(rest)?;
    if method != "publickey" {
        return Err(format!("unsupported authentication method '{method}'"));
    }
    let (&has_sig, rest) = rest
        .split_first()
        .ok_or_else(|| "truncated: expected the signature-present flag".to_string())?;
    if has_sig != 1 {
        return Err("userauth blob is not a signing request".into());
    }
    let (alg, rest) = take_utf8(rest)?;
    if alg != ALG {
        return Err(format!("unsupported key algorithm '{alg}'"));
    }
    let (_key_blob, rest) = take_string(rest)?;
    if !rest.is_empty() {
        return Err("trailing bytes after userauth request".into());
    }
    Ok(SshSignRequest::UserAuth { username, service })
}

/// Sign an SSH payload, refusing anything whose framing we did not recognise.
///
/// Returns `(authorized_keys_line, signature_hex)`. The caller is expected to
/// have shown the user the result of [`classify_request`] and obtained
/// approval - this function does not itself constitute consent.
pub fn sign_request(
    seed_phrase: &str,
    index: u32,
    blob: &[u8],
) -> Result<(String, String), String> {
    // Classify BEFORE signing: an unparseable payload must never be signed,
    // whatever the UI did or did not display.
    let request = classify_request(blob)?;

    let pair = derive_domain_keypair(seed_phrase, SSH_DOMAIN, index)?;

    // For userauth, the blob names the key it expects to be signed with.
    // Refuse when that is not us: signing for a key we do not hold produces a
    // useless signature at best, and at worst lets a caller use us to attack a
    // different identity's session binding.
    if let SshSignRequest::UserAuth { .. } = request {
        let expected = public_key_blob(&pair.public().0);
        if !contains_subslice(blob, &expected) {
            return Err("this request is for a different SSH key than this device holds".into());
        }
    }

    let signature = pair.sign(blob);
    Ok((
        public_key_line(seed_phrase, index, "")?,
        hex::encode(signature.0),
    ))
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    fn pubkey(index: u32) -> [u8; 32] {
        derive_domain_keypair(MNEMONIC, SSH_DOMAIN, index)
            .unwrap()
            .public()
            .0
    }

    fn userauth_blob(pk: &[u8; 32], username: &str) -> Vec<u8> {
        let mut b = ssh_string(b"session-id-bytes");
        b.push(SSH_MSG_USERAUTH_REQUEST);
        b.extend_from_slice(&ssh_string(username.as_bytes()));
        b.extend_from_slice(&ssh_string(b"ssh-connection"));
        b.extend_from_slice(&ssh_string(b"publickey"));
        b.push(1);
        b.extend_from_slice(&ssh_string(ALG.as_bytes()));
        b.extend_from_slice(&ssh_string(&public_key_blob(pk)));
        b
    }

    fn sshsig_blob(namespace: &str) -> Vec<u8> {
        let mut b = SSHSIG_MAGIC.to_vec();
        b.extend_from_slice(&ssh_string(namespace.as_bytes()));
        b.extend_from_slice(&ssh_string(b""));
        b.extend_from_slice(&ssh_string(b"sha512"));
        b.extend_from_slice(&ssh_string(&[0xab; 64]));
        b
    }

    #[test]
    fn public_key_line_has_the_authorized_keys_shape() {
        let line = public_key_line(MNEMONIC, 0, "tommi@zigner").unwrap();
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], ALG);
        assert_eq!(parts[2], "tommi@zigner");

        // The base64 body must decode to the wire blob, and the algorithm name
        // is repeated INSIDE it - that is what makes the line valid to sshd,
        // not just well-shaped.
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let decoded = STANDARD.decode(parts[1]).expect("base64 body");
        assert_eq!(decoded, public_key_blob(&pubkey(0)));
        let (alg, rest) = take_utf8(&decoded).unwrap();
        assert_eq!(alg, ALG);
        assert_eq!(take_string(rest).unwrap().0.len(), 32);
    }

    #[test]
    fn ssh_keys_are_separate_from_the_auth_identity() {
        // Same seed, same index, different domain must give a different key -
        // otherwise "SSH key" and "auth identity" are one authority wearing
        // two names.
        let ssh = hex::encode(pubkey(0));
        let identity = crate::auth::derive_identity(MNEMONIC, 0).unwrap();
        assert_ne!(ssh, identity);
    }

    #[test]
    fn indices_give_distinct_keys() {
        assert_ne!(pubkey(0), pubkey(1));
    }

    #[test]
    fn classifies_a_userauth_request() {
        let blob = userauth_blob(&pubkey(0), "tommi");
        match classify_request(&blob).unwrap() {
            SshSignRequest::UserAuth { username, service } => {
                assert_eq!(username, "tommi");
                assert_eq!(service, "ssh-connection");
            }
            other => panic!("expected UserAuth, got {other:?}"),
        }
    }

    #[test]
    fn classifies_an_sshsig_request() {
        match classify_request(&sshsig_blob("git")).unwrap() {
            SshSignRequest::SshSig {
                namespace,
                hash_algorithm,
                message_hash_hex,
            } => {
                assert_eq!(namespace, "git");
                assert_eq!(hash_algorithm, "sha512");
                assert_eq!(message_hash_hex.len(), 128);
            }
            other => panic!("expected SshSig, got {other:?}"),
        }
    }

    #[test]
    fn refuses_payloads_it_cannot_frame() {
        // The oracle guard: arbitrary bytes must not be signable. A release
        // manifest prefix is the concrete thing we never want signed here.
        for junk in [
            b"zigner-module-v1ZIGM".to_vec(),
            b"".to_vec(),
            vec![0xff; 40],
            vec![0u8, 0, 0, 200, 1, 2, 3],
        ] {
            assert!(
                sign_request(MNEMONIC, 0, &junk).is_err(),
                "signed an unframed payload: {junk:?}"
            );
        }
    }

    #[test]
    fn refuses_a_userauth_request_naming_another_key() {
        let blob = userauth_blob(&pubkey(1), "tommi");
        let err = sign_request(MNEMONIC, 0, &blob).expect_err("must refuse another key's request");
        assert!(err.contains("different SSH key"), "unexpected: {err}");
    }

    #[test]
    fn signs_and_verifies_both_framings() {
        for blob in [userauth_blob(&pubkey(0), "tommi"), sshsig_blob("git")] {
            let (line, sig_hex) = sign_request(MNEMONIC, 0, &blob).expect("sign");
            assert!(line.starts_with(ALG));
            let ok = crate::auth::verify_signature(&hex::encode(pubkey(0)), &sig_hex, &blob)
                .expect("verify");
            assert!(ok, "signature must verify under the SSH-domain key");
        }
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        let full = userauth_blob(&pubkey(0), "tommi");
        for n in 0..full.len() {
            let _ = classify_request(&full[..n]);
        }
        // A string header claiming far more than is present.
        let _ = classify_request(&[0xff, 0xff, 0xff, 0xff, 0x01]);
    }
}
