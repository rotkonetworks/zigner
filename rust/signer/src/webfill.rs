// webfill.rs — answer Zafu's request for a site's password and TOTP code
//
// Zafu takes the site from the browser itself (never from the page), puts
// it in a request QR with a one-time X25519 key, and Zigner answers with a
// QR only that key can open. A camera that sees Zigner's screen learns
// nothing; the user still reads which site is asking before anything is sent.
//
// Zafu and Zigner derive passwords the same way (passwords.rs is zafu's
// scheme 2), so the request carries Zafu's saved login and Zigner derives
// from it directly; nothing has to be set up per site on the phone.
//
// request (text):
//   zigner-pass-request-v1
//   site: github.com        (zafu's normalizeOrigin of the tab's host)
//   login: alice            (may be empty)
//   length: 32
//   rotation: 0
//   key: <64 hex, Zafu's X25519 public key>
//   nonce: <32 hex>
//
// response (one line):
//   zigner-pass-response-v1 <64 hex, Zigner's ephemeral X25519 key> <base64(nonce24 || ciphertext)>
//
//   shared = X25519(ephemeral, zafu key)
//   key    = HKDF-SHA256(salt = request nonce, ikm = shared,
//                        info = "zigner-pass-v1" || zafu key || ephemeral key)
//   ciphertext = XChaCha20-Poly1305(key, nonce24, json, aad = request bytes)
//   json   = {"login": ..., "password": ...?, "totp": ...?}

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::convert::TryInto;
use zeroize::Zeroizing;

use crate::passwords::{normalize_site, Profile};
use crate::totp::Account;

pub const REQUEST_V1: &str = "zigner-pass-request-v1";
pub const RESPONSE_V1: &str = "zigner-pass-response-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub site: String,
    pub login: String,
    pub length: u32,
    pub rotation: u32,
    pub key: [u8; 32],
    pub nonce: [u8; 16],
}

fn hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

impl Request {
    pub fn render(&self) -> String {
        format!(
            "{REQUEST_V1}\nsite: {}\nlogin: {}\nlength: {}\nrotation: {}\nkey: {}\nnonce: {}",
            self.site,
            self.login,
            self.length,
            self.rotation,
            hex::encode(self.key),
            hex::encode(self.nonce)
        )
    }

    /// Strict: exactly the canonical text, or nothing.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = |what: &str| format!("not a Zafu password request ({what})");
        let mut lines = text.split('\n');
        let mut field = |key: &str| lines.next().and_then(|l| l.strip_prefix(key)).ok_or_else(|| bad(key));
        if !field(REQUEST_V1)?.is_empty() {
            return Err(bad("version"));
        }
        let site = field("site: ")?.to_owned();
        let login = field("login: ")?.to_owned();
        let length = field("length: ")?.parse().map_err(|_| bad("length"))?;
        let rotation = field("rotation: ")?.parse().map_err(|_| bad("rotation"))?;
        let key = hex_array(field("key: ")?).ok_or_else(|| bad("key"))?;
        let nonce = hex_array(field("nonce: ")?).ok_or_else(|| bad("nonce"))?;
        if lines.next().is_some() {
            return Err(bad("trailing data"));
        }
        if site.is_empty() || site.len() > 253 || normalize_site(&site) != site {
            return Err(bad("site"));
        }
        if login.len() > 256 || login.chars().any(char::is_control) || login.trim() != login {
            return Err(bad("login"));
        }
        let r = Self { site, login, length, rotation, key, nonce };
        r.profile().map_err(|e| bad(&e))?;
        if r.render() != text {
            return Err(bad("not canonical"));
        }
        Ok(r)
    }

    /// The password this request asks for.
    pub fn profile(&self) -> Result<Profile, String> {
        Profile::new(&self.site, &self.login, self.rotation, self.length)
    }

    /// TOTP accounts whose issuer names this site: "GitHub" for github.com,
    /// or the full host. Shown to the user to confirm, never sent unasked.
    pub fn matching_totp<'a>(&self, accounts: &'a [Account]) -> Vec<(usize, &'a Account)> {
        let labels: Vec<&str> = self.site.split(':').next().unwrap_or("").split('.').collect();
        let brand = labels.len().checked_sub(2).and_then(|i| labels.get(i)).copied().unwrap_or("");
        accounts
            .iter()
            .enumerate()
            .filter(|(_, a)| {
                let issuer = a.issuer.to_lowercase();
                !issuer.is_empty() && (issuer == self.site || issuer == brand || normalize_site(&issuer) == self.site)
            })
            .collect()
    }
}

/// What goes back to Zafu.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Answer {
    pub login: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
}

fn response_key(nonce: &[u8; 16], shared: &[u8; 32], zafu: &[u8; 32], eph: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(14 + 64);
    info.extend_from_slice(b"zigner-pass-v1");
    info.extend_from_slice(zafu);
    info.extend_from_slice(eph);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(nonce), shared)
        .expand(&info, &mut key[..])
        .expect("32 bytes is a valid HKDF length");
    key
}

pub fn respond(request_text: &str, answer: &Answer) -> Result<String, String> {
    let r = Request::parse(request_text)?;
    let eph = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(r.key));
    if !shared.was_contributory() {
        return Err("Zafu's key is invalid".into());
    }
    let key = response_key(&r.nonce, shared.as_bytes(), &r.key, eph_pub.as_bytes());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let pt = Zeroizing::new(serde_json::to_vec(answer).map_err(|e| e.to_string())?);
    let ct = XChaCha20Poly1305::new((&*key).into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &pt, aad: request_text.as_bytes() })
        .map_err(|_| "encryption failed")?;
    let body = base64::engine::general_purpose::STANDARD.encode([&nonce[..], &ct].concat());
    Ok(format!("{RESPONSE_V1} {} {body}", hex::encode(eph_pub.as_bytes())))
}

/// Zafu's half, here so the tests pin both directions.
pub fn open(request_text: &str, zafu_secret: &[u8; 32], response: &str) -> Result<Answer, String> {
    let r = Request::parse(request_text)?;
    let mut f = response.trim().split(' ');
    let (tag, eph, body) = (f.next(), f.next(), f.next());
    if tag != Some(RESPONSE_V1) || f.next().is_some() {
        return Err("not a Zigner password response".into());
    }
    let eph: [u8; 32] = eph.and_then(hex_array).ok_or("bad ephemeral key")?;
    let body = base64::engine::general_purpose::STANDARD.decode(body.ok_or("no body")?).map_err(|_| "bad body")?;
    if body.len() < 24 + 16 {
        return Err("short body".into());
    }
    let secret = x25519_dalek::StaticSecret::from(*zafu_secret);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(eph));
    let key = response_key(&r.nonce, shared.as_bytes(), &r.key, &eph);
    let pt = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(XNonce::from_slice(&body[..24]), Payload { msg: &body[24..], aad: request_text.as_bytes() })
            .map_err(|_| "response does not belong to this request")?,
    );
    serde_json::from_slice(&pt).map_err(|e| e.to_string())
}

/// The answer the user approved: the password, the TOTP code, or both.
pub fn answer(seed_phrase: &str, request: &Request, password: bool, totp: Option<&Account>, now: u64) -> Result<Answer, String> {
    if !password && totp.is_none() {
        return Err("nothing to send".into());
    }
    let pw = if password { Some(request.profile()?.password(seed_phrase)?.to_string()) } else { None };
    Ok(Answer { login: request.login.clone(), password: pw, totp: totp.map(|a| a.code_at(now)) })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn request(site: &str, login: &str) -> (String, [u8; 32]) {
        let secret = [5u8; 32];
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        let r = Request { site: site.into(), login: login.into(), length: 32, rotation: 0, key: *public.as_bytes(), nonce: [9; 16] };
        (r.render(), secret)
    }

    #[test]
    fn roundtrip_and_binding() {
        let (text, secret) = request("github.com", "alice");
        let r = Request::parse(&text).unwrap();
        let accounts = [
            Account::from_uri("otpauth://totp/GitHub:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub").unwrap(),
            Account::from_uri("otpauth://totp/Gitlab:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        ];
        assert_eq!(r.matching_totp(&accounts).iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0]);

        let a = answer(SEED, &r, true, Some(&accounts[0]), 59).unwrap();
        let line = respond(&text, &a).unwrap();
        let got = open(&text, &secret, &line).unwrap();
        assert_eq!(got.login, "alice");
        assert_eq!(got.password.as_deref(), Some("G<)WH@t!d3S!<_&~+V~p{_SA!wh3H{3s"));
        assert_eq!(got.totp.as_deref(), Some("287082"));

        // Bound to the request: another site's request, or another key, cannot open it.
        let (other, _) = request("evil.example", "alice");
        assert!(open(&other, &secret, &line).is_err());
        assert!(open(&text, &[6u8; 32], &line).is_err());
        assert!(answer(SEED, &r, false, None, 0).is_err());
    }

    #[test]
    fn strict_requests() {
        let (text, _) = request("github.com", "");
        assert!(Request::parse(&text).is_ok());
        for bad in [
            text.replace("github.com", "GitHub.com"),
            text.replace("github.com", "https://github.com"),
            text.replace("github.com", ""),
            text.replace("login: ", "login:  alice"),
            format!("{text}\n"),
            text.replace("-v1", "-v2"),
            text.replace("key: ", "key: 00"),
            text.replace("length: 32", "length: 64"),
            text.replace("rotation: 0", "rotation: -1"),
            text.replace("rotation: 0", "rotation: 00"),
        ] {
            if bad != text {
                assert!(Request::parse(&bad).is_err(), "{:?}", bad);
            }
        }
    }

    /// Fixed inputs, for Zafu's TypeScript side to check its decryption
    /// against (the ephemeral key is random, so this prints a fresh one).
    #[test]
    #[ignore]
    fn print_vector() {
        let (text, _) = request("github.com", "alice");
        let a = Answer { login: "alice".into(), password: Some("G<)WH@t!d3S!<_&~+V~p{_SA!wh3H{3s".into()), totp: Some("287082".into()) };
        println!("SECRET={}", hex::encode([5u8; 32]));
        println!("REQUEST={}", serde_json::to_string(&text).unwrap());
        println!("RESPONSE={}", respond(&text, &a).unwrap());
    }
}
