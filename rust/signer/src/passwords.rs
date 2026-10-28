// passwords.rs — site passwords derived from the seed (v1)
//
// A password is a pure function of (seed, site, login, counter, policy), so
// the seed phrase alone restores every one of them. The vault only keeps the
// profile (which sites, which rules) so nothing has to be remembered.
//
//   root   = HKDF-SHA256(salt = "zigner-pass-v1", ikm = SHA-256(mnemonic), info = "root")
//   input  = lp(site) || lp(login) || counter(u32 BE) || policy encoding
//   stream = HKDF-Expand(prk = HMAC-SHA256(root, input), info = "stream", 4096 bytes)
//
// lp(x) is a u32 BE length prefix followed by the bytes. The policy is part
// of the input, so a 16-character password is not a prefix of the
// 20-character one. Characters are drawn by rejection sampling (no modulo
// bias); a candidate missing a required class is discarded whole and the next
// one is drawn from the same stream, so the output stays deterministic.
//
// FROZEN: the vectors in the tests pin this derivation. Changing it changes
// every password a user has registered anywhere. Rotate with the counter.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_FIELD_LEN: usize = 256;
const STREAM_LEN: usize = 4096;
pub const DEFAULT_SYMBOLS: &str = "!#$%&*+-=?@^_";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy {
    /// Random characters, for pasting.
    #[serde(rename = "c")]
    Chars { length: u32, lower: bool, upper: bool, digits: bool, symbols: String },
    /// BIP39 words, for typing by hand from the phone screen. With
    /// `decorate`, each word is capitalized and a digit is appended, which
    /// satisfies most "upper + digit" rules.
    #[serde(rename = "w")]
    Words { count: u32, separator: String, decorate: bool },
}

impl Default for Policy {
    /// Words: the phone shows the password and a person types it.
    fn default() -> Self {
        Self::Words { count: 5, separator: "-".into(), decorate: true }
    }
}

impl Policy {
    pub fn chars_default() -> Self {
        Self::Chars { length: 20, lower: true, upper: true, digits: true, symbols: DEFAULT_SYMBOLS.into() }
    }

    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Chars { length, lower, upper, digits, symbols } => {
                if !(8..=128).contains(length) {
                    return Err("length must be 8..=128".into());
                }
                if !symbols.chars().all(|c| c.is_ascii_graphic() && !c.is_ascii_alphanumeric()) {
                    return Err("symbols must be printable ASCII punctuation".into());
                }
                let mut seen = std::collections::BTreeSet::new();
                if !symbols.chars().all(|c| seen.insert(c)) {
                    return Err("symbols must not repeat".into());
                }
                if !(*lower || *upper || *digits || !symbols.is_empty()) {
                    return Err("enable at least one character class".into());
                }
                let classes = [*lower, *upper, *digits, !symbols.is_empty()].iter().filter(|&&c| c).count();
                if (*length as usize) < classes {
                    return Err("length is shorter than the number of required classes".into());
                }
            }
            Self::Words { count, separator, .. } => {
                if !(3..=24).contains(count) {
                    return Err("word count must be 3..=24".into());
                }
                if separator.chars().count() > 4 || separator.chars().any(|c| c.is_control()) {
                    return Err("separator must be at most 4 printable characters".into());
                }
            }
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Chars { length, lower, upper, digits, symbols } => {
                out.push(b'c');
                out.extend_from_slice(&length.to_be_bytes());
                out.push(u8::from(*lower) | u8::from(*upper) << 1 | u8::from(*digits) << 2);
                lp(&mut out, symbols.as_bytes());
            }
            Self::Words { count, separator, decorate } => {
                out.push(b'w');
                out.extend_from_slice(&count.to_be_bytes());
                lp(&mut out, separator.as_bytes());
                out.push(u8::from(*decorate));
            }
        }
        out
    }
}

/// What the vault stores for a site: enough to regenerate, never the password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    #[serde(rename = "s")]
    pub site: String,
    #[serde(rename = "l")]
    pub login: String,
    #[serde(rename = "n")]
    pub counter: u32,
    #[serde(rename = "p")]
    pub policy: Policy,
}

impl Profile {
    pub fn new(site: &str, login: &str, counter: u32, policy: Policy) -> Result<Self, String> {
        let p = Self { site: normalize_site(site), login: login.trim().to_owned(), counter, policy };
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
        self.policy.validate()
    }

    pub fn same_site(&self, other: &Self) -> bool {
        self.site == other.site && self.login == other.login
    }

    pub fn password(&self, seed_phrase: &str) -> Result<Zeroizing<String>, String> {
        self.validate()?;
        derive(seed_phrase, self)
    }
}

/// `https://www.GitHub.com/login` → `github.com`. Shown to the user before
/// saving, since a different spelling is a different password.
pub fn normalize_site(site: &str) -> String {
    let s = site.trim().to_lowercase();
    let s = s.split_once("://").map_or(s.as_str(), |(_, rest)| rest);
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit_once('@').map_or(s, |(_, host)| host);
    s.strip_prefix("www.").unwrap_or(s).trim_end_matches('.').to_owned()
}

fn lp(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn root(seed_phrase: &str) -> Zeroizing<[u8; 32]> {
    let ikm = Zeroizing::new(Sha256::digest(seed_phrase.as_bytes()));
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"zigner-pass-v1"), &ikm[..])
        .expand(b"root", &mut key[..])
        .expect("32 bytes is a valid HKDF length");
    key
}

fn stream(seed_phrase: &str, p: &Profile) -> Zeroizing<Vec<u8>> {
    let mut input = Vec::new();
    lp(&mut input, p.site.as_bytes());
    lp(&mut input, p.login.as_bytes());
    input.extend_from_slice(&p.counter.to_be_bytes());
    input.extend_from_slice(&p.policy.encode());
    let root = root(seed_phrase);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&root[..]).expect("HMAC takes any key length");
    mac.update(&input);
    let prk = Zeroizing::new(mac.finalize().into_bytes());
    let mut out = Zeroizing::new(vec![0u8; STREAM_LEN]);
    Hkdf::<Sha256>::from_prk(&prk)
        .expect("32-byte PRK")
        .expand(b"stream", &mut out)
        .expect("4096 bytes is a valid HKDF length");
    out
}

/// Pulls unbiased indices below `n` from the stream.
struct Draw<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Draw<'_> {
    fn below(&mut self, n: usize) -> Result<usize, String> {
        debug_assert!(n > 0 && n <= 65536);
        let wide = n > 256;
        let space = if wide { 65536 } else { 256 };
        let limit = space - space % n;
        loop {
            let v = if wide {
                let b = self.bytes.get(self.pos..self.pos + 2).ok_or(EXHAUSTED)?;
                self.pos += 2;
                usize::from(u16::from_be_bytes([b[0], b[1]]))
            } else {
                let b = *self.bytes.get(self.pos).ok_or(EXHAUSTED)?;
                self.pos += 1;
                usize::from(b)
            };
            if v < limit {
                return Ok(v % n);
            }
        }
    }
}

const EXHAUSTED: &str = "password policy is too strict to satisfy";

fn derive(seed_phrase: &str, p: &Profile) -> Result<Zeroizing<String>, String> {
    let bytes = stream(seed_phrase, p);
    let mut d = Draw { bytes: &bytes, pos: 0 };
    match &p.policy {
        Policy::Chars { length, lower, upper, digits, symbols } => {
            let classes: Vec<Vec<char>> = vec![
                (*lower, ('a'..='z').collect::<Vec<_>>()),
                (*upper, ('A'..='Z').collect()),
                (*digits, ('0'..='9').collect()),
                (!symbols.is_empty(), symbols.chars().collect()),
            ]
            .into_iter()
            .filter_map(|(on, set)| on.then_some(set))
            .collect();
            let alphabet: Vec<char> = classes.concat();
            loop {
                let mut pw = Zeroizing::new(String::with_capacity(*length as usize));
                for _ in 0..*length {
                    pw.push(alphabet[d.below(alphabet.len())?]);
                }
                if classes.iter().all(|set| pw.chars().any(|c| set.contains(&c))) {
                    return Ok(pw);
                }
            }
        }
        Policy::Words { count, separator, decorate } => {
            let list = bip39::Language::English.wordlist();
            let mut pw = Zeroizing::new(String::new());
            for i in 0..*count {
                if i > 0 {
                    pw.push_str(separator);
                }
                let word = list.get_word((d.below(2048)? as u16).into());
                if *decorate {
                    let mut c = word.chars();
                    pw.extend(c.next().map(|f| f.to_ascii_uppercase()));
                    pw.push_str(c.as_str());
                } else {
                    pw.push_str(word);
                }
            }
            if *decorate {
                pw.push(char::from(b'0' + d.below(10)? as u8));
            }
            Ok(pw)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn pw(site: &str, login: &str, counter: u32, policy: Policy) -> String {
        Profile::new(site, login, counter, policy).unwrap().password(SEED).unwrap().to_string()
    }

    #[test]
    fn frozen_vectors() {
        // If these change, every derived password changes. Do not update
        // them; add a v2 instead.
        let got = [
            pw("github.com", "alice", 1, Policy::chars_default()),
            pw("github.com", "alice", 2, Policy::chars_default()),
            pw("github.com", "alice", 1, Policy::default()),
            pw(
                "bank.example",
                "",
                1,
                Policy::Chars { length: 12, lower: false, upper: false, digits: true, symbols: String::new() },
            ),
        ];
        let want: [&str; 4] = include!("passwords_vectors.in");
        assert_eq!(got, want);
    }

    #[test]
    fn properties() {
        let a = pw("github.com", "alice", 1, Policy::chars_default());
        assert_eq!(a.chars().count(), 20);
        assert!(a.chars().any(|c| c.is_ascii_lowercase()));
        assert!(a.chars().any(|c| c.is_ascii_uppercase()));
        assert!(a.chars().any(|c| c.is_ascii_digit()));
        assert!(a.chars().any(|c| DEFAULT_SYMBOLS.contains(c)));
        // Same site however it's written; anything else changes it.
        assert_eq!(a, pw("https://www.GitHub.com/login?x=1", " alice ", 1, Policy::chars_default()));
        assert_ne!(a, pw("github.com", "bob", 1, Policy::chars_default()));
        assert_ne!(a, pw("gitlab.com", "alice", 1, Policy::chars_default()));
        // A shorter policy is not a prefix of the longer one.
        let short = pw(
            "github.com",
            "alice",
            1,
            Policy::Chars { length: 16, lower: true, upper: true, digits: true, symbols: DEFAULT_SYMBOLS.into() },
        );
        assert!(!a.starts_with(&short));
        // Another seed, another password.
        let other = Profile::new("github.com", "alice", 1, Policy::chars_default())
            .unwrap()
            .password("legal winner thank year wave sausage worth useful legal winner thank yellow")
            .unwrap();
        assert_ne!(a, *other);

        let w = pw("github.com", "alice", 1, Policy::default());
        let parts: Vec<&str> = w.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|p| p.chars().next().unwrap().is_ascii_uppercase()));
        assert!(w.ends_with(|c: char| c.is_ascii_digit()));
    }

    #[test]
    fn rejects_bad_profiles() {
        let bad = |p: Policy| Profile::new("a.example", "x", 1, p).is_err();
        assert!(bad(Policy::Chars { length: 7, lower: true, upper: true, digits: true, symbols: String::new() }));
        assert!(bad(Policy::Chars { length: 20, lower: false, upper: false, digits: false, symbols: String::new() }));
        assert!(bad(Policy::Chars { length: 20, lower: true, upper: false, digits: false, symbols: "a".into() }));
        assert!(bad(Policy::Chars { length: 20, lower: true, upper: false, digits: false, symbols: "!!".into() }));
        assert!(bad(Policy::Words { count: 2, separator: "-".into(), decorate: false }));
        assert!(Profile::new("", "x", 1, Policy::default()).is_err());
        assert!(Profile::new("a.example", "x\n", 1, Policy::default()).is_ok(), "login is trimmed");
        assert!(Profile::new("a.example", "x\ny", 1, Policy::default()).is_err());
    }

    #[test]
    fn normalizes_sites() {
        for (input, want) in [
            ("GitHub.com", "github.com"),
            ("https://www.github.com/login", "github.com"),
            ("http://user@mail.example.org:8443/x", "mail.example.org:8443"),
            ("example.com.", "example.com"),
        ] {
            assert_eq!(normalize_site(input), want, "{}", input);
        }
    }

    /// Distribution sanity: digits-only over many counters is roughly uniform.
    #[test]
    fn no_obvious_bias() {
        let mut counts = [0u32; 10];
        for n in 0..200 {
            let p = pw(
                "bias.example",
                "",
                n,
                Policy::Chars { length: 50, lower: false, upper: false, digits: true, symbols: String::new() },
            );
            for c in p.chars() {
                counts[(c as u8 - b'0') as usize] += 1;
            }
        }
        // 10000 draws, expected 1000 each; 5 sigma ≈ 150.
        assert!(counts.iter().all(|&c| (850..1150).contains(&c)), "{:?}", counts);
    }
}
