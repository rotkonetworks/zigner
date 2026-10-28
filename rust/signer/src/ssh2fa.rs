// ssh2fa.rs — approve SSH certificate requests from an ssh2fa server
//
// ssh2fad hands `ssh2fa login` a plain-text request; Zafu (or a terminal)
// shows it as a QR. Zigner shows every field and, on approval, signs the
// exact bytes with an Ed25519 key it derives for that server:
//
//   identity = HMAC-SHA512(zid_root, "identity:default")       (as auth.rs v2)
//   seed     = HMAC-SHA512(identity, "ssh2fa:" + origin)[..32]
//
// The "ssh2fa:" tag is a separate branch from ZID's "site:" keys, so no
// sign-in QR can make Zigner produce an ssh2fa approval. Only text that
// parses as a request, and re-renders to the same bytes, is ever signed.
//
// The request format is ssh2fa's crates/api/src/approval.rs; the vector in
// the tests is shared with it.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use sp_core::{ed25519, Pair};
use std::convert::TryInto;
use zeroize::Zeroizing;

pub const REQUEST_V1: &str = "ssh2fa-cert-request-v1";
pub const APPROVAL_V1: &str = "ssh2fa-cert-approval-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertRequest {
    /// Server name, without the `ssh2fa://` scheme.
    pub origin: String,
    pub user: String,
    pub principals: Vec<String>,
    pub ttl: u64,
    pub keys: Vec<String>,
    pub nonce: String,
    pub issued: u64,
}

fn name_ok(s: &str, extra: &[u8]) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

impl CertRequest {
    pub fn render(&self) -> String {
        format!(
            "{REQUEST_V1}\norigin: ssh2fa://{}\nuser: {}\nprincipals: {}\nttl: {}\nkeys: {}\nnonce: {}\nissued: {}",
            self.origin,
            self.user,
            self.principals.join(","),
            self.ttl,
            self.keys.join(" "),
            self.nonce,
            self.issued
        )
    }

    /// Strict: exactly the canonical text, or nothing.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = |what: &str| format!("not an ssh2fa request ({what})");
        let mut lines = text.split('\n');
        let mut field = |key: &str| -> Result<&str, String> {
            lines.next().and_then(|l| l.strip_prefix(key)).ok_or_else(|| bad(key.trim_end_matches(": ")))
        };
        if !field(REQUEST_V1)?.is_empty() {
            return Err(bad("version"));
        }
        let origin = field("origin: ssh2fa://")?.to_owned();
        let user = field("user: ")?.to_owned();
        let principals: Vec<String> = field("principals: ")?.split(',').map(str::to_owned).collect();
        let ttl = field("ttl: ")?.parse().map_err(|_| bad("ttl"))?;
        let keys: Vec<String> = field("keys: ")?.split(' ').map(str::to_owned).collect();
        let nonce = field("nonce: ")?.to_owned();
        let issued = field("issued: ")?.parse().map_err(|_| bad("issued"))?;
        if lines.next().is_some() {
            return Err(bad("trailing data"));
        }
        let r = Self { origin, user, principals, ttl, keys, nonce, issued };
        if !name_ok(&r.origin, b".-:") || !name_ok(&r.user, b"._-") {
            return Err(bad("origin or user"));
        }
        if r.principals.is_empty() || r.principals.len() > 16 || !r.principals.iter().all(|p| name_ok(p, b"._@-")) {
            return Err(bad("principals"));
        }
        let key_ok = |k: &String| {
            k.strip_prefix("SHA256:").is_some_and(|b| {
                !b.is_empty() && b.len() <= 64 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
            })
        };
        if r.keys.is_empty() || r.keys.len() > 2 || !r.keys.iter().all(key_ok) {
            return Err(bad("keys"));
        }
        if r.nonce.len() != 32 || !r.nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(bad("nonce"));
        }
        if r.ttl == 0 || r.ttl > 30 * 86400 {
            return Err(bad("ttl"));
        }
        if r.render() != text {
            return Err(bad("not canonical"));
        }
        Ok(r)
    }
}

fn approval_pair(seed_phrase: &str, origin: &str) -> Result<ed25519::Pair, String> {
    type HmacSha512 = Hmac<Sha512>;
    let root = Zeroizing::new(crate::auth::derive_zid_root(seed_phrase)?);
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&root[..]).map_err(|e| format!("hmac: {e}"))?;
    mac.update(b"identity:default");
    let identity = Zeroizing::new(mac.finalize().into_bytes());
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&identity).map_err(|e| format!("hmac: {e}"))?;
    mac.update(format!("ssh2fa:{origin}").as_bytes());
    let out = Zeroizing::new(mac.finalize().into_bytes());
    let seed: [u8; 32] = out[..32].try_into().map_err(|_| "seed slice")?;
    Ok(ed25519::Pair::from_seed(&seed))
}

/// The key an ssh2fa admin registers with `ssh2fa approver add`, hex.
pub fn approver_pubkey(seed_phrase: &str, origin: &str) -> Result<String, String> {
    if !name_ok(origin, b".-:") {
        return Err("server name: letters, digits, '.', '-' and ':' only".into());
    }
    Ok(hex::encode(approval_pair(seed_phrase, origin)?.public().0))
}

/// Signs a request the user has seen and approved. Returns the line ssh2fa
/// expects back.
pub fn approve(seed_phrase: &str, text: &str) -> Result<String, String> {
    let r = CertRequest::parse(text)?;
    let pair = approval_pair(seed_phrase, &r.origin)?;
    let sig = pair.sign(text.as_bytes());
    Ok(format!("{APPROVAL_V1} {} {} {}", r.nonce, hex::encode(pair.public().0), hex::encode(sig.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// ssh2fa crates/api/src/approval.rs, test VECTOR.
    const VECTOR: &str = "ssh2fa-cert-request-v1\norigin: ssh2fa://prod.example\nuser: alice\nprincipals: alice,deploy\nttl: 28800\nkeys: SHA256:abc SHA256:def\nnonce: 00112233445566778899aabbccddeeff\nissued: 1793216533";

    #[test]
    fn parses_and_renders_the_shared_vector() {
        let r = CertRequest::parse(VECTOR).unwrap();
        assert_eq!(r.origin, "prod.example");
        assert_eq!(r.principals, ["alice", "deploy"]);
        assert_eq!(r.ttl, 28800);
        assert_eq!(r.render(), VECTOR);
    }

    #[test]
    fn refuses_anything_else() {
        for bad in [
            VECTOR.replace("-v1", "-v2"),
            format!("{VECTOR}\n"),
            format!("{VECTOR}\nextra: 1"),
            VECTOR.replace("ttl: 28800", "ttl: 028800"),
            VECTOR.replace("ttl: 28800", "ttl: 0"),
            VECTOR.replace("principals: alice,deploy", "principals: alice,,deploy"),
            VECTOR.replace("principals: alice,deploy", "principals: root\nuser: x"),
            VECTOR.replace("user: alice", "user: al ice"),
            VECTOR.replace("origin: ssh2fa://", "origin: https://"),
            VECTOR.replace("SHA256:abc", "MD5:abc"),
            VECTOR.replace("00112233", "0011223"),
            VECTOR.replace('\n', "\r\n"),
            "ssh2fa-cert-request-v1".into(),
        ] {
            assert!(CertRequest::parse(&bad).is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn approval_verifies_and_keys_are_per_server() {
        let line = approve(SEED, VECTOR).unwrap();
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!((f[0], f[1]), (APPROVAL_V1, "00112233445566778899aabbccddeeff"));
        assert_eq!(f[2], approver_pubkey(SEED, "prod.example").unwrap());
        let pk = ed25519::Public::from_raw(hex::decode(f[2]).unwrap().try_into().unwrap());
        let sig = ed25519::Signature::from_raw(hex::decode(f[3]).unwrap().try_into().unwrap());
        assert!(ed25519::Pair::verify(&sig, VECTOR.as_bytes(), &pk));

        assert_ne!(approver_pubkey(SEED, "prod.example"), approver_pubkey(SEED, "staging.example"));
        // Not any ZID site key for the same name.
        let (_, zid_pk) = crate::auth::sign_zid_challenge(SEED, "default", "site", "prod.example", 0, b"x").unwrap();
        assert_ne!(f[2], zid_pk);
        let (_, zid_pk) = crate::auth::sign_zid_challenge(SEED, "default", "site", "ssh2fa://prod.example", 0, b"x").unwrap();
        assert_ne!(f[2], zid_pk);
        // Frozen: the key an admin registered must not change.
        assert_eq!(approver_pubkey(SEED, "prod.example").unwrap(), include_str!("ssh2fa_vector.in").trim());
    }

    /// For testing against a live ssh2fad: prints the approval line for
    /// `SSH2FA_REQUEST` under `SSH2FA_SEED` (default: the test seed).
    #[test]
    #[ignore]
    fn approve_from_env() {
        let seed = std::env::var("SSH2FA_SEED").unwrap_or_else(|_| SEED.into());
        if let Ok(origin) = std::env::var("SSH2FA_ORIGIN") {
            println!("SSH2FA_PUBKEY={}", approver_pubkey(&seed, &origin).unwrap());
        }
        if let Ok(req) = std::env::var("SSH2FA_REQUEST") {
            println!("SSH2FA_APPROVAL={}", approve(&seed, &req).unwrap());
        }
    }
}
