// totp.rs — offline TOTP authenticator with a seed-encrypted vault
//
// Accounts come from a website's otpauth:// QR. The secret is the site's, so
// it cannot be derived and has to be stored. It is stored only inside the
// vault, sealed under a key derived from the seed phrase:
//
//   vault_key = HKDF-SHA256(salt = "zigner-totp-v1", ikm = SHA-256(mnemonic), info = "vault-key")
//   blob      = "ZTV1" || generation(u64 BE) || count(u32 BE) || nonce(24) || XChaCha20-Poly1305(json)
//   aad       = "zigner-totp-vault\0" || header (magic, generation, count)
//
// The sealed blob is also the backup. It is useless without the seed, so it
// can be printed or kept anywhere: restore = seed phrase + latest blob. The
// header stays readable without the seed so the UI can show "N accounts not
// backed up" (generation vs. the last exported generation) while locked.
//
// Time: the device is offline, so the clock is the weak point. Codes are
// refused when the clock is before a fixed floor or well before the latest
// time this device has shown codes for (a reset RTC), and a user-confirmed
// offset from a scanned time QR corrects drift without touching the system
// clock. That clock state is not secret and lives beside the vault, so
// showing codes never changes the backup.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use crate::passwords::Profile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::convert::TryInto;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 4] = b"ZTV1";
const HEADER_LEN: usize = 4 + 8 + 4;
const NONCE_LEN: usize = 24;
const AAD_DOMAIN: &[u8] = b"zigner-totp-vault\0";
const MAX_ENTRIES: usize = 1000;
const MAX_FIELD_LEN: usize = 256;
/// RFC 4226 requires 128 bits; real sites hand out 80-bit secrets.
const MIN_SECRET_LEN: usize = 10;
const MAX_SECRET_LEN: usize = 128;
const MAX_BLOB_LEN: usize = 256 * 1024;

/// No genuine clock reads earlier than this (2026-01-01T00:00:00Z).
pub const CLOCK_FLOOR: u64 = 1_767_225_600;
/// A scanned time QR may correct the clock by at most this much.
pub const MAX_CLOCK_OFFSET: i64 = 7 * 24 * 3600;
/// Seconds a stored "latest seen" time may be ahead before we call the clock
/// rewound. Covers a user nudging the clock back a little.
const REWIND_TOLERANCE: u64 = 300;
const LATEST_SEEN_STEP: u64 = 60;

/// Text form of a backup, for printing or pasting. The QR carries the raw bytes.
pub const BACKUP_TEXT_PREFIX: &str = "zigner-totp-vault:";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
// One-letter keys: the sealed vault is sized for QR codes.
pub struct Account {
    #[serde(rename = "i")]
    pub issuer: String,
    #[serde(rename = "l")]
    pub label: String,
    #[serde(rename = "s", with = "secret_b64")]
    secret: Vec<u8>,
    #[serde(rename = "a")]
    #[zeroize(skip)]
    pub algorithm: Algorithm,
    #[serde(rename = "d")]
    pub digits: u32,
    #[serde(rename = "p")]
    pub period: u64,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("issuer", &self.issuer)
            .field("label", &self.label)
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

impl Account {
    /// Parses `otpauth://totp/Issuer:label?secret=...&issuer=...`.
    pub fn from_uri(uri: &str) -> Result<Self, String> {
        let rest = strip_prefix_ci(uri.trim(), "otpauth://")
            .ok_or("not an otpauth:// QR code")?;
        let (kind, rest) = rest.split_once('/').ok_or("malformed otpauth URI")?;
        match kind.to_ascii_lowercase().as_str() {
            "totp" => {}
            "hotp" => return Err("HOTP (counter-based) codes are not supported, only TOTP".into()),
            _ => return Err(format!("unknown otpauth type {kind:?}")),
        }
        let (path, query) = rest.split_once('?').ok_or("otpauth URI has no parameters")?;
        let path = percent_decode(path)?;
        let (path_issuer, label) = match path.split_once(':') {
            Some((i, l)) => (Some(i.trim().to_owned()), l.trim().to_owned()),
            None => (None, path.trim().to_owned()),
        };

        let mut secret = None;
        let mut issuer = None;
        let (mut algorithm, mut digits, mut period) = (Algorithm::Sha1, 6, 30);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v)?;
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(Zeroizing::new(base32_decode(&v)?)),
                "issuer" => issuer = Some(v),
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(format!("unsupported algorithm {v:?}")),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| "digits is not a number")?,
                "period" => period = v.parse().map_err(|_| "period is not a number")?,
                _ => {} // image=, color= and other vendor extras
            }
        }
        let issuer = issuer.or(path_issuer).unwrap_or_default();
        let secret = secret.ok_or("otpauth URI has no secret")?;
        let account = Self { issuer, label, secret: secret.to_vec(), algorithm, digits, period };
        account.validate()?;
        Ok(account)
    }

    fn validate(&self) -> Result<(), String> {
        for (name, v) in [("issuer", &self.issuer), ("label", &self.label)] {
            if v.len() > MAX_FIELD_LEN || v.chars().any(char::is_control) {
                return Err(format!("{name} is too long or contains control characters"));
            }
        }
        if self.issuer.is_empty() && self.label.is_empty() {
            return Err("account has neither issuer nor label".into());
        }
        if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&self.secret.len()) {
            return Err(format!("secret must be {MIN_SECRET_LEN}..={MAX_SECRET_LEN} bytes"));
        }
        if !(6..=8).contains(&self.digits) {
            return Err("digits must be 6, 7 or 8".into());
        }
        if !(1..=300).contains(&self.period) {
            return Err("period must be 1..=300 seconds".into());
        }
        Ok(())
    }

    /// The code valid at `unix_time`, zero-padded.
    pub fn code_at(&self, unix_time: u64) -> String {
        let v = hotp(&self.secret, unix_time / self.period, self.algorithm, self.digits);
        format!("{v:0width$}", width = self.digits as usize)
    }

    /// Seconds until the code at `unix_time` rolls over.
    pub fn seconds_left(&self, unix_time: u64) -> u64 {
        self.period - unix_time % self.period
    }

    /// The account as an otpauth:// URI, for export (KeePass `otp` field).
    pub fn to_uri(&self) -> Zeroizing<String> {
        let enc = |s: &str| -> String {
            s.bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => (b as char).to_string(),
                    _ => format!("%{b:02X}"),
                })
                .collect()
        };
        let path = if self.issuer.is_empty() {
            enc(&self.label)
        } else {
            format!("{}:{}", enc(&self.issuer), enc(&self.label))
        };
        Zeroizing::new(format!(
            "otpauth://totp/{path}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            base32_encode(&self.secret).as_str(),
            enc(&self.issuer),
            self.algorithm.name(),
            self.digits,
            self.period
        ))
    }

    fn same_as(&self, other: &Self) -> bool {
        self.issuer == other.issuer && self.label == other.label && self.secret == other.secret
    }
}

/// RFC 4226 HOTP with RFC 6238's SHA-2 variants.
pub fn hotp(key: &[u8], counter: u64, alg: Algorithm, digits: u32) -> u32 {
    fn mac<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = <M as Mac>::new_from_slice(key).expect("HMAC takes any key length");
        m.update(msg);
        m.finalize().into_bytes().to_vec()
    }
    let msg = counter.to_be_bytes();
    let h = Zeroizing::new(match alg {
        Algorithm::Sha1 => mac::<Hmac<sha1::Sha1>>(key, &msg),
        Algorithm::Sha256 => mac::<Hmac<Sha256>>(key, &msg),
        Algorithm::Sha512 => mac::<Hmac<Sha512>>(key, &msg),
    });
    let o = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) & 0x7fff_ffff;
    bin % 10u32.pow(digits)
}

#[derive(Default, Serialize, Deserialize)]
struct Plain {
    #[serde(rename = "a")]
    accounts: Vec<Account>,
    /// Derived-password site profiles (see passwords.rs).
    #[serde(rename = "p", default)]
    profiles: Vec<Profile>,
}

impl Plain {
    fn len(&self) -> usize {
        self.accounts.len() + self.profiles.len()
    }
}

/// The decrypted vault. Mutations bump the generation when sealed.
pub struct Vault {
    generation: u64,
    plain: Plain,
}

/// What the header says, readable without the seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub generation: u64,
    pub count: u32,
}

pub fn read_header(blob: &[u8]) -> Result<Header, String> {
    if blob.len() < HEADER_LEN + NONCE_LEN + 16 || blob.len() > MAX_BLOB_LEN || &blob[..4] != MAGIC {
        return Err("not a Zigner TOTP vault".into());
    }
    let generation = u64::from_be_bytes(blob[4..12].try_into().expect("8 bytes"));
    let count = u32::from_be_bytes(blob[12..16].try_into().expect("4 bytes"));
    Ok(Header { generation, count })
}

struct VaultKey(Zeroizing<[u8; 32]>);

fn vault_key(seed_phrase: &str) -> VaultKey {
    let ikm = Zeroizing::new(Sha256::digest(seed_phrase.as_bytes()));
    let hk = Hkdf::<Sha256>::new(Some(b"zigner-totp-v1"), &ikm[..]);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"vault-key", &mut key[..]).expect("32 bytes is a valid HKDF length");
    VaultKey(key)
}

fn aad(header: &[u8]) -> Vec<u8> {
    [AAD_DOMAIN, header].concat()
}

impl Vault {
    pub fn new() -> Self {
        Self { generation: 0, plain: Plain::default() }
    }

    pub fn open(seed_phrase: &str, blob: &[u8]) -> Result<Self, String> {
        let header = read_header(blob)?;
        let (head, rest) = blob.split_at(HEADER_LEN);
        let (nonce, ct) = rest.split_at(NONCE_LEN);
        let key = vault_key(seed_phrase);
        let pt = Zeroizing::new(
            XChaCha20Poly1305::new((&*key.0).into())
                .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad(head) })
                .map_err(|_| "this vault belongs to a different seed, or it is damaged")?,
        );
        let plain: Plain = serde_json::from_slice(&pt).map_err(|e| format!("vault contents: {e}"))?;
        if plain.len() != header.count as usize || plain.len() > MAX_ENTRIES {
            return Err("vault header does not match its contents".into());
        }
        for a in &plain.accounts {
            a.validate()?;
        }
        for p in &plain.profiles {
            p.validate()?;
        }
        Ok(Self { generation: header.generation, plain })
    }

    /// Seals the vault as the next generation.
    pub fn seal(&mut self, seed_phrase: &str) -> Result<Vec<u8>, String> {
        self.generation = self.generation.checked_add(1).ok_or("vault generation overflow")?;
        let mut blob = Vec::with_capacity(HEADER_LEN + NONCE_LEN + 100 * self.plain.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&self.generation.to_be_bytes());
        blob.extend_from_slice(&(self.plain.len() as u32).to_be_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        blob.extend_from_slice(&nonce);
        let pt = Zeroizing::new(serde_json::to_vec(&self.plain).map_err(|e| e.to_string())?);
        let key = vault_key(seed_phrase);
        let ct = XChaCha20Poly1305::new((&*key.0).into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &pt, aad: &aad(&blob[..HEADER_LEN]) })
            .map_err(|_| "vault encryption failed")?;
        blob.extend_from_slice(&ct);
        Ok(blob)
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn accounts(&self) -> &[Account] {
        &self.plain.accounts
    }

    pub fn add(&mut self, account: Account) -> Result<usize, String> {
        account.validate()?;
        if self.plain.accounts.iter().any(|a| a.same_as(&account)) {
            return Err("this account is already in the vault".into());
        }
        if self.plain.len() >= MAX_ENTRIES {
            return Err(format!("the vault holds at most {MAX_ENTRIES} entries"));
        }
        self.plain.accounts.push(account);
        Ok(self.plain.accounts.len() - 1)
    }

    pub fn remove(&mut self, index: usize) -> Result<Account, String> {
        if index >= self.plain.accounts.len() {
            return Err("no such account".into());
        }
        Ok(self.plain.accounts.remove(index))
    }

    pub fn profiles(&self) -> &[Profile] {
        &self.plain.profiles
    }

    /// Adds a site profile; one per (site, login).
    pub fn add_profile(&mut self, profile: Profile) -> Result<usize, String> {
        profile.validate()?;
        if self.plain.profiles.iter().any(|p| p.same_site(&profile)) {
            return Err("there is already a password for this site and login".into());
        }
        if self.plain.len() >= MAX_ENTRIES {
            return Err(format!("the vault holds at most {MAX_ENTRIES} entries"));
        }
        self.plain.profiles.push(profile);
        Ok(self.plain.profiles.len() - 1)
    }

    /// Replaces a profile, e.g. to bump its counter after a password change.
    pub fn update_profile(&mut self, index: usize, profile: Profile) -> Result<(), String> {
        profile.validate()?;
        if self.plain.profiles.iter().enumerate().any(|(i, p)| i != index && p.same_site(&profile)) {
            return Err("there is already a password for this site and login".into());
        }
        *self.plain.profiles.get_mut(index).ok_or("no such site")? = profile;
        Ok(())
    }

    pub fn remove_profile(&mut self, index: usize) -> Result<Profile, String> {
        if index >= self.plain.profiles.len() {
            return Err("no such site".into());
        }
        Ok(self.plain.profiles.remove(index))
    }

    /// Adds every entry of `other` not already here. Returns how many. For a
    /// site in both, the higher counter wins: it is the newer password.
    pub fn merge(&mut self, other: Vault) -> Result<usize, String> {
        let mut added = 0;
        for a in other.plain.accounts.iter() {
            if !self.plain.accounts.iter().any(|b| b.same_as(a)) {
                self.add(a.clone())?;
                added += 1;
            }
        }
        for p in other.plain.profiles.iter() {
            match self.plain.profiles.iter_mut().find(|q| q.same_site(p)) {
                Some(q) if q.counter < p.counter => *q = p.clone(),
                Some(_) => {}
                None => {
                    self.add_profile(p.clone())?;
                    added += 1;
                }
            }
        }
        self.generation = self.generation.max(other.generation);
        Ok(added)
    }

}

/// The device clock as TOTP sees it. Not secret and not per seed, so it lives
/// outside the vault: updating it must not make the backup look stale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Clock {
    /// User-confirmed correction to the device clock, in seconds.
    pub offset: i64,
    /// Latest corrected time a code was shown for; catches a rewound clock.
    pub latest_seen: u64,
}

impl Clock {
    /// The corrected time for `device_time`, or why codes must not be shown.
    /// Records the result as the latest time seen.
    pub fn now(&mut self, device_time: u64) -> Result<u64, ClockError> {
        let now = device_time.saturating_add_signed(self.offset);
        if now < CLOCK_FLOOR {
            return Err(ClockError::BeforeFloor { now });
        }
        if now + REWIND_TOLERANCE < self.latest_seen {
            return Err(ClockError::Rewound { now, latest_seen: self.latest_seen });
        }
        // Minute granularity: the guard tolerates 300 s anyway, and this keeps
        // a once-a-second code screen from writing to flash every second.
        if now >= self.latest_seen.saturating_add(LATEST_SEEN_STEP) {
            self.latest_seen = now;
        }
        Ok(now)
    }

    /// Offset that makes the device clock read `reference_time` now. The UI
    /// shows both times and calls `set_offset` only after the user confirms.
    pub fn proposed_offset(device_time: u64, reference_time: u64) -> Result<i64, String> {
        if reference_time < CLOCK_FLOOR {
            return Err("the scanned time is before 2026; refusing it".into());
        }
        let offset = reference_time as i128 - device_time as i128;
        if offset.unsigned_abs() > MAX_CLOCK_OFFSET as u128 {
            return Err("the device clock is off by more than 7 days; set the date in system settings first".into());
        }
        Ok(offset as i64)
    }

    pub fn set_offset(&mut self, offset: i64) -> Result<(), String> {
        if offset.unsigned_abs() > MAX_CLOCK_OFFSET as u64 {
            return Err("clock offset out of range".into());
        }
        self.offset = offset;
        // A deliberate correction may move the clock back.
        self.latest_seen = 0;
        Ok(())
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClockError {
    BeforeFloor { now: u64 },
    Rewound { now: u64, latest_seen: u64 },
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeFloor { .. } => write!(f, "the device clock is wrong (before 2026); scan a time QR or set the date"),
            Self::Rewound { now, latest_seen } => write!(
                f,
                "the device clock went backwards ({}s behind the last time seen); scan a time QR to correct it",
                latest_seen - now
            ),
        }
    }
}

/// Parses a time QR: `zigner-time-v1:<unix seconds>`.
pub fn parse_time_qr(text: &str) -> Result<u64, String> {
    text.trim()
        .strip_prefix("zigner-time-v1:")
        .ok_or("not a Zigner time QR code")?
        .parse()
        .map_err(|_| "time QR does not hold a number".into())
}

pub fn backup_to_text(blob: &[u8]) -> String {
    use base64::Engine;
    format!("{BACKUP_TEXT_PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(blob))
}

/// Accepts either the raw QR bytes or the text form.
pub fn backup_from_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    use base64::Engine;
    if data.starts_with(MAGIC) {
        return Ok(data.to_vec());
    }
    let text = std::str::from_utf8(data).map_err(|_| "not a Zigner TOTP vault")?;
    let b64 = text.trim().strip_prefix(BACKUP_TEXT_PREFIX).ok_or("not a Zigner TOTP vault")?;
    base64::engine::general_purpose::STANDARD
        .decode(b64.split_whitespace().collect::<String>())
        .map_err(|_| "backup text is damaged".into())
}

/// Secrets as base64 strings in the sealed JSON, not number arrays: about a
/// quarter of the size, which is what decides how many accounts fit one QR.
mod secret_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(v)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        base64::engine::general_purpose::STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes()))
        .then(|| &s[prefix.len()..])
}

fn percent_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b.get(i + 1..i + 3).ok_or("bad percent-encoding")?;
                let hex = std::str::from_utf8(hex).map_err(|_| "bad percent-encoding")?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| "bad percent-encoding")?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "otpauth URI is not UTF-8".into())
}

/// RFC 4648 base32 without padding, as otpauth URIs carry it.
fn base32_encode(b: &[u8]) -> Zeroizing<String> {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Zeroizing::new(String::with_capacity((b.len() * 8).div_ceil(5)));
    let (mut acc, mut bits) = (0u64, 0u32);
    for &x in b {
        acc = (acc << 8) | u64::from(x);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    acc.zeroize();
    out
}

/// RFC 4648 base32, case-insensitive, padding and spaces ignored.
fn base32_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u64, 0u32);
    for c in s.bytes().filter(|c| !matches!(c, b' ' | b'-' | b'=')) {
        let v = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return Err("secret is not valid base32".into()),
        };
        acc = (acc << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    acc.zeroize();
    Ok(out)
}

/// Persistence in sled: one sealed vault per seed name, the generation last
/// confirmed as backed up, and the device clock state.
pub mod store {
    use super::*;
    use constants::TOTP_TREE;

    const CLOCK_KEY: &[u8] = b"clock";

    fn key(prefix: &str, seed_name: &str) -> Vec<u8> {
        [prefix.as_bytes(), seed_name.as_bytes()].concat()
    }

    fn tree(db: &sled::Db) -> Result<sled::Tree, String> {
        db.open_tree(TOTP_TREE).map_err(|e| format!("database: {e}"))
    }

    fn get(db: &sled::Db, k: &[u8]) -> Result<Option<Vec<u8>>, String> {
        Ok(tree(db)?.get(k).map_err(|e| format!("database: {e}"))?.map(|v| v.to_vec()))
    }

    fn put(db: &sled::Db, k: &[u8], v: &[u8]) -> Result<(), String> {
        let t = tree(db)?;
        t.insert(k, v).map_err(|e| format!("database: {e}"))?;
        t.flush().map_err(|e| format!("database: {e}"))?;
        Ok(())
    }

    fn get_u64(db: &sled::Db, k: &[u8]) -> Result<u64, String> {
        Ok(match get(db, k)? {
            Some(v) => u64::from_be_bytes(v.as_slice().try_into().map_err(|_| "database: bad u64")?),
            None => 0,
        })
    }

    /// The sealed vault for `seed_name`, as stored (and as exported).
    pub fn blob(db: &sled::Db, seed_name: &str) -> Result<Option<Vec<u8>>, String> {
        get(db, &key("vault:", seed_name))
    }

    pub fn open(db: &sled::Db, seed_name: &str, seed_phrase: &str) -> Result<Vault, String> {
        match blob(db, seed_name)? {
            Some(b) => Vault::open(seed_phrase, &b),
            None => Ok(Vault::new()),
        }
    }

    /// Seals `vault` as its next generation and stores it.
    pub fn save(db: &sled::Db, seed_name: &str, seed_phrase: &str, vault: &mut Vault) -> Result<Header, String> {
        let b = vault.seal(seed_phrase)?;
        put(db, &key("vault:", seed_name), &b)?;
        read_header(&b)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Status {
        pub has_vault: bool,
        pub accounts: u32,
        pub generation: u64,
        pub backed_up_generation: u64,
    }

    impl Status {
        pub fn needs_backup(&self) -> bool {
            self.accounts > 0 && self.backed_up_generation != self.generation
        }
    }

    /// Readable without the seed, for the "not backed up" badge.
    pub fn status(db: &sled::Db, seed_name: &str) -> Result<Status, String> {
        let backed_up_generation = get_u64(db, &key("backed-up:", seed_name))?;
        Ok(match blob(db, seed_name)? {
            Some(b) => {
                let h = read_header(&b)?;
                Status { has_vault: true, accounts: h.count, generation: h.generation, backed_up_generation }
            }
            None => Status { has_vault: false, accounts: 0, generation: 0, backed_up_generation },
        })
    }

    /// The user says the export of `generation` is saved somewhere.
    pub fn confirm_backup(db: &sled::Db, seed_name: &str, generation: u64) -> Result<(), String> {
        let current = status(db, seed_name)?.generation;
        if generation != current {
            return Err("the vault changed since this backup was shown; export it again".into());
        }
        put(db, &key("backed-up:", seed_name), &generation.to_be_bytes())
    }

    /// Restores a backup made under the same seed. Into an empty vault it is
    /// stored as is (and so already backed up); otherwise it is merged.
    /// Returns how many accounts were added.
    pub fn restore(db: &sled::Db, seed_name: &str, seed_phrase: &str, backup: &[u8]) -> Result<u32, String> {
        let backup = backup_from_bytes(backup)?;
        let incoming = Vault::open(seed_phrase, &backup)?;
        let n = incoming.accounts().len() as u32;
        let mut current = open(db, seed_name, seed_phrase)?;
        if current.accounts().is_empty() {
            let generation = incoming.generation().max(current.generation());
            if generation == incoming.generation() {
                put(db, &key("vault:", seed_name), &backup)?;
                put(db, &key("backed-up:", seed_name), &generation.to_be_bytes())?;
                return Ok(n);
            }
        }
        let added = current.merge(incoming)? as u32;
        save(db, seed_name, seed_phrase, &mut current)?;
        Ok(added)
    }

    pub fn clock(db: &sled::Db) -> Result<Clock, String> {
        Ok(match get(db, CLOCK_KEY)? {
            Some(v) if v.len() == 16 => Clock {
                offset: i64::from_be_bytes(v[..8].try_into().expect("8 bytes")),
                latest_seen: u64::from_be_bytes(v[8..].try_into().expect("8 bytes")),
            },
            Some(_) => return Err("database: bad clock record".into()),
            None => Clock::default(),
        })
    }

    pub fn save_clock(db: &sled::Db, clock: &Clock) -> Result<(), String> {
        put(db, CLOCK_KEY, &[clock.offset.to_be_bytes(), clock.latest_seen.to_be_bytes()].concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn rfc6238_vectors() {
        let k1 = b"12345678901234567890";
        let k256 = b"12345678901234567890123456789012";
        let k512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        for (t, sha1, sha256, sha512) in [
            (59u64, 94287082u32, 46119246u32, 90693936u32),
            (1111111109, 7081804, 68084774, 25091201),
            (1111111111, 14050471, 67062674, 99943326),
            (1234567890, 89005924, 91819424, 93441116),
            (2000000000, 69279037, 90698825, 38618901),
            (20000000000, 65353130, 77737706, 47863826),
        ] {
            assert_eq!(hotp(k1, t / 30, Algorithm::Sha1, 8), sha1, "sha1 t={t}");
            assert_eq!(hotp(k256, t / 30, Algorithm::Sha256, 8), sha256, "sha256 t={t}");
            assert_eq!(hotp(k512, t / 30, Algorithm::Sha512, 8), sha512, "sha512 t={t}");
        }
    }

    #[test]
    fn parses_otpauth() {
        // "12345678901234567890" in base32, as GitHub-style lowercase with spaces.
        let a = Account::from_uri(
            "otpauth://totp/ACME%20Co:alice@example.com?secret=gezd gnbv gy3t qojq gezd gnbv gy3t qojq&issuer=ACME+Co&period=30",
        )
        .unwrap();
        assert_eq!((a.issuer.as_str(), a.label.as_str()), ("ACME Co", "alice@example.com"));
        assert_eq!(a.code_at(59), "287082");
        assert_eq!(a.seconds_left(59), 1);

        let b = Account::from_uri("otpauth://totp/ssh2fa:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8").unwrap();
        assert_eq!(b.issuer, "ssh2fa");
        assert_eq!(b.algorithm, Algorithm::Sha256);
        assert_eq!(b.code_at(59), "46119246");

        for bad in [
            "https://example.com",
            "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
            "otpauth://totp/x?issuer=nosecret",
            "otpauth://totp/x?secret=GEZDGNBV", // 5 bytes
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ1",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=10",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
            "otpauth://totp/a%0Ab?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        ] {
            assert!(Account::from_uri(bad).is_err(), "{}", bad);
        }
    }

    fn account(label: &str) -> Account {
        Account::from_uri(&format!("otpauth://totp/{label}?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")).unwrap()
    }

    #[test]
    fn vault_roundtrip_and_header() {
        let mut v = Vault::new();
        v.add(account("one")).unwrap();
        v.add(account("two")).unwrap();
        assert!(v.add(account("one")).is_err(), "duplicate");
        let blob = v.seal(SEED).unwrap();
        assert_eq!(read_header(&blob).unwrap(), Header { generation: 1, count: 2 });

        let mut w = Vault::open(SEED, &blob).unwrap();
        assert_eq!(w.accounts().iter().map(|a| a.label.as_str()).collect::<Vec<_>>(), ["one", "two"]);
        w.remove(0).unwrap();
        let blob2 = w.seal(SEED).unwrap();
        assert_eq!(read_header(&blob2).unwrap(), Header { generation: 2, count: 1 });

        assert!(Vault::open("legal winner thank year wave sausage worth useful legal winner thank yellow", &blob).is_err());
        // The header is authenticated: a doctored generation or count fails.
        let mut forged = blob.clone();
        forged[11] ^= 1;
        assert!(Vault::open(SEED, &forged).is_err());
        let mut forged = blob.clone();
        forged[15] ^= 1;
        assert!(Vault::open(SEED, &forged).is_err());
        let mut forged = blob;
        *forged.last_mut().unwrap() ^= 1;
        assert!(Vault::open(SEED, &forged).is_err());
    }

    #[test]
    fn backup_text_and_restore_merge() {
        let mut phone = Vault::new();
        phone.add(account("one")).unwrap();
        let backup = phone.seal(SEED).unwrap();
        let text = backup_to_text(&backup);
        assert_eq!(backup_from_bytes(text.as_bytes()).unwrap(), backup);
        assert_eq!(backup_from_bytes(&backup).unwrap(), backup);

        let mut new_phone = Vault::new();
        new_phone.add(account("two")).unwrap();
        let restored = Vault::open(SEED, &backup_from_bytes(text.as_bytes()).unwrap()).unwrap();
        assert_eq!(new_phone.merge(restored).unwrap(), 1);
        assert_eq!(new_phone.accounts().len(), 2);
        let blob = new_phone.seal(SEED).unwrap();
        assert_eq!(read_header(&blob).unwrap().generation, 2);
    }

    #[test]
    fn clock_guards() {
        let mut c = Clock::default();
        let t = CLOCK_FLOOR + 1_000_000;
        assert_eq!(c.now(t), Ok(t));
        // RTC reset to 1970 after a dead battery.
        assert_eq!(c.now(0), Err(ClockError::BeforeFloor { now: 0 }));
        // Small step back is tolerated, a big one is not.
        assert_eq!(c.now(t - 60), Ok(t - 60));
        assert!(matches!(c.now(t - 3600), Err(ClockError::Rewound { .. })));

        // Time QR correction: device is 90 s slow.
        let off = Clock::proposed_offset(t, t + 90).unwrap();
        assert_eq!(off, 90);
        c.set_offset(off).unwrap();
        assert_eq!(c.now(t), Ok(t + 90));
        assert!(Clock::proposed_offset(t, t + 8 * 24 * 3600).is_err());
        assert!(Clock::proposed_offset(t, 1000).is_err());
        assert!(c.set_offset(MAX_CLOCK_OFFSET + 1).is_err());
        assert_eq!(parse_time_qr("zigner-time-v1:1767225600\n"), Ok(1767225600));
        assert!(parse_time_qr("zigner-time-v1:soon").is_err());
    }

    #[test]
    fn store_backup_badge_and_restore() {
        let dir = std::env::temp_dir().join(format!("zigner-totp-{}", std::process::id()));
        let db = sled::open(&dir).unwrap();
        let st = |db| store::status(db, "main").unwrap();
        assert!(!st(&db).has_vault);

        let mut v = store::open(&db, "main", SEED).unwrap();
        v.add(account("one")).unwrap();
        let h = store::save(&db, "main", SEED, &mut v).unwrap();
        assert!(st(&db).needs_backup());
        let backup = store::blob(&db, "main").unwrap().unwrap();
        assert!(store::confirm_backup(&db, "main", h.generation + 1).is_err());
        store::confirm_backup(&db, "main", h.generation).unwrap();
        assert!(!st(&db).needs_backup());

        // Codes never touch the vault, so the badge stays clear.
        let mut c = store::clock(&db).unwrap();
        c.now(CLOCK_FLOOR + 10).unwrap();
        store::save_clock(&db, &c).unwrap();
        assert_eq!(store::clock(&db).unwrap(), c);
        assert!(!st(&db).needs_backup());

        let mut v = store::open(&db, "main", SEED).unwrap();
        v.add(account("two")).unwrap();
        store::save(&db, "main", SEED, &mut v).unwrap();
        assert!(st(&db).needs_backup());

        // New phone: restoring into an empty vault is already backed up.
        assert_eq!(store::restore(&db, "fresh", SEED, &backup).unwrap(), 1);
        assert!(!store::status(&db, "fresh").unwrap().needs_backup());
        // Merging an old backup into the newer vault adds nothing.
        assert_eq!(store::restore(&db, "main", SEED, backup_to_text(&backup).as_bytes()).unwrap(), 0);
        assert_eq!(store::open(&db, "main", SEED).unwrap().accounts().len(), 2);
        // Wrong seed is refused, nothing changes.
        assert!(store::restore(&db, "fresh", "legal winner thank year wave sausage worth useful legal winner thank yellow", &backup).is_err());

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Prints the current code for `ZIGNER_TOTP_URI` (an ssh2fa enroll URI),
    /// for checking against a live ssh2fad: `ssh2fa check <user> <code>`.
    #[test]
    #[ignore]
    fn code_for_uri_from_env() {
        let uri = std::env::var("ZIGNER_TOTP_URI").expect("set ZIGNER_TOTP_URI");
        let a = Account::from_uri(&uri).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        println!("ZIGNER_CODE={}", a.code_at(now));
    }

    #[test]
    fn sealed_size_per_account() {
        let mut v = Vault::new();
        for i in 0..25 {
            v.add(account(&format!("GitHub:user{}@example.com", i))).unwrap();
        }
        let n = v.seal(SEED).unwrap().len();
        // One QR (version 40, binary, ECC L) holds 2953 bytes.
        assert!(n < 2953, "25 accounts sealed to {} bytes", n);
    }

    #[test]
    fn uri_roundtrip() {
        let a = Account::from_uri("otpauth://totp/ACME%20Co:al%20ice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8&period=60").unwrap();
        let b = Account::from_uri(&a.to_uri()).unwrap();
        assert!(a.same_as(&b));
        assert_eq!((b.algorithm, b.digits, b.period), (Algorithm::Sha256, 8, 60));
        for n in 10..=40 {
            let secret: Vec<u8> = (0..n as u8).collect();
            assert_eq!(base32_decode(&base32_encode(&secret)).unwrap(), secret);
        }
    }

    #[test]
    fn vault_holds_profiles() {
        use crate::passwords::Policy;
        let mut v = Vault::new();
        v.add(account("one")).unwrap();
        v.add_profile(Profile::new("github.com", "alice", 1, Policy::default()).unwrap()).unwrap();
        assert!(v.add_profile(Profile::new("GitHub.com", "alice", 3, Policy::default()).unwrap()).is_err());
        let blob = v.seal(SEED).unwrap();
        assert_eq!(read_header(&blob).unwrap().count, 2);
        let mut w = Vault::open(SEED, &blob).unwrap();
        // Restoring an older backup must not roll a bumped counter back.
        w.update_profile(0, Profile::new("github.com", "alice", 2, Policy::default()).unwrap()).unwrap();
        w.merge(Vault::open(SEED, &blob).unwrap()).unwrap();
        assert_eq!(w.profiles()[0].counter, 2);
        let mut old = Vault::open(SEED, &blob).unwrap();
        old.merge(w).unwrap();
        assert_eq!(old.profiles()[0].counter, 2);
    }

    #[test]
    fn debug_redacts_secret() {
        let s = format!("{:?}", account("one"));
        assert!(s.contains("<redacted>") && !s.contains("49, 50"), "{}", s);
    }
}
