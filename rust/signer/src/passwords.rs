// passwords.rs — site passwords derived from the seed, Zafu's scheme v2
//
// Byte for byte the derivation in zafu's apps/extension/src/state/identity.ts
// (derivePassword, scheme 2), so one seed gives the same password for a site
// whether it lives in a hot Zafu wallet or on Zigner:
//
//   identity = HMAC-SHA512(zid_root, "identity:default")          (auth.rs v2)
//   tag      = "password:v2" || lp(site) || lp(username) || u32be(rotation)
//   seed     = HMAC-SHA512(identity, tag)
//   password = base85(seed[..32]) cut to `length` (at most 40)
//
// lp(x) is a u32 BE length prefix, then the bytes. `site` is normalized as
// zafu's normalizeOrigin does, with the same frozen public-suffix list. The
// vectors in the tests were produced by zafu's own code.
//
// FROZEN: changing any of this changes passwords people use. Rotate instead.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroizing;

const MAX_FIELD_LEN: usize = 256;
/// 32 bytes, 8 groups of at most 5 base85 characters.
pub const MAX_LENGTH: u32 = 40;
pub const LENGTHS: [u32; 4] = [16, 24, 32, 40];
pub const DEFAULT_LENGTH: u32 = 32;

/// RFC 1924 base85 alphabet, as zafu uses it.
const B85: &[u8; 85] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

/// What the vault stores for a site: enough to regenerate, never the password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    #[serde(rename = "s")]
    pub site: String,
    #[serde(rename = "l")]
    pub login: String,
    /// Bumped when a site forces a new password.
    #[serde(rename = "r")]
    pub rotation: u32,
    #[serde(rename = "n")]
    pub length: u32,
}

impl Profile {
    pub fn new(site: &str, login: &str, rotation: u32, length: u32) -> Result<Self, String> {
        let p = Self { site: normalize_site(site), login: login.trim().to_owned(), rotation, length };
        p.validate()?;
        Ok(p)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.site.is_empty() {
            return Err("site must not be empty".into());
        }
        for (name, v) in [("site", &self.site), ("login", &self.login)] {
            if v.len() > MAX_FIELD_LEN || v.chars().any(char::is_control) {
                return Err(format!("{name} is too long or contains control characters"));
            }
        }
        if !(8..=MAX_LENGTH).contains(&self.length) {
            return Err(format!("length must be 8..={MAX_LENGTH}"));
        }
        Ok(())
    }

    pub fn same_site(&self, other: &Self) -> bool {
        self.site == other.site && self.login == other.login
    }

    pub fn password(&self, seed_phrase: &str) -> Result<Zeroizing<String>, String> {
        self.validate()?;
        let identity = identity(seed_phrase)?;
        Ok(derive(&identity, &self.site, &self.login, self.length, self.rotation))
    }
}

/// zafu's `identityKey(mnemonic)`: the default identity node.
fn identity(seed_phrase: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let root = Zeroizing::new(crate::auth::derive_zid_root(seed_phrase)?);
    Ok(Zeroizing::new(hmac512(&root[..], b"identity:default")))
}

fn hmac512(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn lp(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn derive(identity: &[u8], site: &str, login: &str, length: u32, rotation: u32) -> Zeroizing<String> {
    let mut tag = b"password:v2".to_vec();
    lp(&mut tag, site.as_bytes());
    lp(&mut tag, login.as_bytes());
    tag.extend_from_slice(&rotation.to_be_bytes());
    let seed = Zeroizing::new(hmac512(identity, &tag));
    let bytes = &seed[..32];
    let length = length.min(MAX_LENGTH) as usize;
    let mut out = Zeroizing::new(String::with_capacity(length));
    for group in bytes.chunks(4) {
        let mut val = group.iter().fold(0u32, |v, &b| (v << 8) | u32::from(b));
        for _ in 0..5 {
            if out.len() >= length {
                return out;
            }
            out.push(B85[(val % 85) as usize] as char);
            val /= 85;
        }
    }
    out
}

/// Second-level labels that country-code registries hand out to the public.
const CC_SECOND_LEVEL: &[&str] = &[
    "ac", "biz", "co", "com", "ed", "edu", "firm", "gen", "go", "gob", "gouv", "gov", "gr", "govt", "id", "ind",
    "info", "lg", "ltd", "me", "mil", "ne", "net", "nhs", "nic", "nom", "or", "org", "plc", "sch", "web",
];

/// Suffixes under which unrelated people publish their own pages.
const SHARED_HOSTING: &[&str] = &[
    "appspot.com",
    "azurestaticapps.net",
    "azurewebsites.net",
    "blogspot.com",
    "cloudfront.net",
    "codeberg.page",
    "deno.dev",
    "firebaseapp.com",
    "fly.dev",
    "github.io",
    "gitlab.io",
    "glitch.me",
    "herokuapp.com",
    "ngrok.io",
    "ngrok-free.app",
    "netlify.app",
    "onrender.com",
    "pages.dev",
    "r2.dev",
    "railway.app",
    "replit.app",
    "s3.amazonaws.com",
    "surge.sh",
    "translate.goog",
    "vercel.app",
    "web.app",
    "workers.dev",
];

fn is_password_suffix(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() <= 1 || SHARED_HOSTING.contains(&domain) {
        return true;
    }
    labels.len() == 2 && labels[1].len() == 2 && CC_SECOND_LEVEL.contains(&labels[0])
}

const COMMON_LABELS: &[&str] =
    &["www", "api", "app", "login", "auth", "sso", "accounts", "mail", "my", "portal", "secure", "id"];

/// zafu's `normalizeOrigin`: scheme, path and port go; one common leading
/// label goes while what is left is still a registrable domain.
/// `https://www.forum.z.cash/x` → `forum.z.cash`, but `mail.com` stays.
pub fn normalize_site(raw: &str) -> String {
    let mut host = raw.trim().to_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(rest) = host.strip_prefix(scheme) {
            host = rest.to_owned();
            break;
        }
    }
    if let Some(i) = host.find('/') {
        host.truncate(i);
    }
    if let Some(i) = host.rfind(':') {
        let port = &host[i + 1..];
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            host.truncate(i);
        }
    }
    let rest = host
        .split_once('.')
        .filter(|(label, _)| COMMON_LABELS.contains(label))
        .map(|(_, rest)| rest.to_owned());
    match rest {
        Some(rest) if !is_password_suffix(&rest) => rest,
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn pw(site: &str, login: &str, rotation: u32, length: u32) -> String {
        Profile::new(site, login, rotation, length).unwrap().password(SEED).unwrap().to_string()
    }

    /// Produced by zafu's derivePassword (scheme 2) for the same seed.
    #[test]
    fn matches_zafu() {
        assert_eq!(pw("github.com", "alice", 0, 32), "G<)WH@t!d3S!<_&~+V~p{_SA!wh3H{3s");
        assert_eq!(pw("github.com", "alice", 1, 32), "aJ<ywf2l|3kY)Ay-cZB0p~7{JO^w$S?I");
        assert_eq!(pw("https://www.bbc.co.uk/x", "", 0, 40), "~^u7sqjxK5Yh{r7L!osD@!`Ih~LeGF1a&Mmh%iL{");
        assert_eq!(pw("login.github.com", "alice", 0, 16), "G<)WH@t!d3S!<_&~");
        assert_eq!(normalize_site("https://www.forum.z.cash:8443/path?x=1"), "forum.z.cash");
    }

    /// zafu's own normalization cases (derive-password.test.ts).
    #[test]
    fn normalization_matches_zafu() {
        for (raw, want) in [
            ("https://www.forum.z.cash/path?x=1", "forum.z.cash"),
            ("login.github.com", "github.com"),
            ("mail.com", "mail.com"),
            ("mail.ru", "mail.ru"),
            ("id.me", "id.me"),
            ("my.co.uk", "my.co.uk"),
            ("www.bbc.co.uk", "bbc.co.uk"),
            ("app.github.io", "app.github.io"),
            ("www.alice.github.io", "alice.github.io"),
            ("localhost:8080", "localhost"),
        ] {
            assert_eq!(normalize_site(raw), want, "{}", raw);
        }
    }

    #[test]
    fn properties() {
        let a = pw("github.com", "alice", 0, 32);
        assert_eq!(a.len(), 32);
        assert_eq!(derive(&identity(SEED).unwrap(), "github.com", "alice", 48, 0).len(), 40, "caps at 40 like zafu");
        assert_ne!(a, pw("github.com", "bob", 0, 32));
        assert_ne!(pw("a.example", "b", 0, 32), pw("a.exampl", "eb", 0, 32));
        let other = Profile::new("github.com", "alice", 0, 32)
            .unwrap()
            .password("legal winner thank year wave sausage worth useful legal winner thank yellow")
            .unwrap();
        assert_ne!(a, *other);
        assert!(Profile::new("", "x", 0, 32).is_err());
        assert!(Profile::new("a.example", "x\ny", 0, 32).is_err());
        assert!(Profile::new("a.example", "x", 0, 7).is_err());
    }
}
