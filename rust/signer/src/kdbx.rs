// kdbx.rs — write a KeePass (KDBX 4) database
//
// The escape hatch from Zigner: a password-protected file that KeePassXC and
// other KeePass apps open without Zigner or the seed. Only what Zigner holds
// goes in: entries with title, login, URL, password and an `otp` field.
//
// Layout (constants from KeePassXC src/format/KeePass2.{h,cpp}):
//
//   sig1 sig2 version(4.0)  header fields (id u8, len u32 LE, data) ... end
//   SHA-256(header)  HMAC-SHA256(block key u64::MAX, header)
//   HMAC block stream of ChaCha20(gzip(inner header || XML))
//
//   composite   = SHA-256(SHA-256(password))
//   transformed = Argon2id(composite, salt, params)
//   cipher key  = SHA-256(master seed || transformed)
//   hmac key    = SHA-512(master seed || transformed || 0x01)
//   block key i = SHA-512(i u64 LE || hmac key)
//
// Protected values (Password, otp) are additionally XORed with the inner
// ChaCha20 stream (key/nonce = SHA-512(inner key)[0..32]/[32..44]) in
// document order, as KeePass does for in-memory protection.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use std::io::Write;
use zeroize::Zeroizing;

const SIG1: u32 = 0x9AA2_D903;
const SIG2: u32 = 0xB54B_FB67;
const VERSION_4_0: u32 = 0x0004_0000;
const CIPHER_CHACHA20: [u8; 16] = uuid(0xd6038a2b_8b6f_4cb5_a524_339a31dbb59a);
const KDF_ARGON2ID: [u8; 16] = uuid(0x9e298b19_56db_4773_b23d_fc3ec6f0a1e6);
const INNER_STREAM_CHACHA20: u32 = 3;
const BLOCK_SIZE: usize = 1 << 20;

const fn uuid(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

/// Argon2id cost. The phone does this once per export, so the defaults are
/// KeePassXC-like, not cheap.
#[derive(Clone, Copy, Debug)]
pub struct Kdf {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Kdf {
    fn default() -> Self {
        Self { memory_kib: 64 * 1024, iterations: 4, parallelism: 2 }
    }
}

#[derive(Default)]
pub struct Entry {
    pub title: String,
    pub username: String,
    pub url: String,
    pub password: Option<Zeroizing<String>>,
    /// otpauth:// URI, KeePassXC's TOTP format.
    pub otp: Option<Zeroizing<String>>,
    pub notes: String,
}

/// One entry per TOTP account and per site password. Derived passwords are
/// computed here, so the file stands alone without the seed.
pub fn entries_from_vault(vault: &crate::totp::Vault, seed_phrase: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    for a in vault.accounts() {
        let title = if a.issuer.is_empty() { &a.label } else { &a.issuer };
        entries.push(Entry {
            title: format!("{title} (TOTP)"),
            username: a.label.clone(),
            otp: Some(a.to_uri()),
            notes: "TOTP from Zigner".into(),
            ..Default::default()
        });
    }
    for p in vault.profiles() {
        entries.push(Entry {
            title: p.site.clone(),
            username: p.login.clone(),
            url: format!("https://{}", p.site),
            password: Some(p.password(seed_phrase)?),
            notes: format!("Derived by Zigner (passwords v1, counter {}). The seed regenerates it.", p.counter),
            ..Default::default()
        });
    }
    Ok(entries)
}

pub fn write(name: &str, entries: &[Entry], password: &str, kdf: Kdf) -> Result<Vec<u8>, String> {
    if password.is_empty() {
        return Err("the KeePass file needs a password".into());
    }
    let mut master_seed = [0u8; 32];
    let mut iv = [0u8; 12];
    let mut salt = [0u8; 32];
    let mut inner_key = Zeroizing::new([0u8; 64]);
    OsRng.fill_bytes(&mut master_seed);
    OsRng.fill_bytes(&mut iv);
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut inner_key[..]);

    // Outer header.
    let mut kdf_params = Vec::new();
    kdf_params.extend_from_slice(&0x0100u16.to_le_bytes());
    variant(&mut kdf_params, 0x42, "$UUID", &KDF_ARGON2ID);
    variant(&mut kdf_params, 0x42, "S", &salt);
    variant(&mut kdf_params, 0x04, "P", &kdf.parallelism.to_le_bytes());
    variant(&mut kdf_params, 0x05, "M", &(u64::from(kdf.memory_kib) * 1024).to_le_bytes());
    variant(&mut kdf_params, 0x05, "I", &u64::from(kdf.iterations).to_le_bytes());
    variant(&mut kdf_params, 0x04, "V", &0x13u32.to_le_bytes());
    kdf_params.push(0);

    let mut out = Vec::new();
    out.extend_from_slice(&SIG1.to_le_bytes());
    out.extend_from_slice(&SIG2.to_le_bytes());
    out.extend_from_slice(&VERSION_4_0.to_le_bytes());
    field(&mut out, 2, &CIPHER_CHACHA20);
    field(&mut out, 3, &1u32.to_le_bytes()); // gzip
    field(&mut out, 4, &master_seed);
    field(&mut out, 7, &iv);
    field(&mut out, 11, &kdf_params);
    field(&mut out, 0, b"\r\n\r\n");

    // Keys.
    let composite = Zeroizing::new(Sha256::digest(Sha256::digest(password.as_bytes())));
    let mut transformed = Zeroizing::new([0u8; 32]);
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|e| format!("argon2 parameters: {e}"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(&composite, &salt, &mut transformed[..])
        .map_err(|e| format!("argon2: {e}"))?;
    let cipher_key = Zeroizing::new(Sha256::new().chain_update(master_seed).chain_update(&transformed[..]).finalize());
    let hmac_key = Zeroizing::new(
        Sha512::new()
            .chain_update(master_seed)
            .chain_update(&transformed[..])
            .chain_update([1u8])
            .finalize(),
    );

    let header_hash = Sha256::digest(&out);
    let header_hmac = hmac256(&block_key(u64::MAX, &hmac_key)[..], &[&out]);
    out.extend_from_slice(&header_hash);
    out.extend_from_slice(&header_hmac);

    // Payload: inner header, then XML with protected values.
    let mut inner = Zeroizing::new(Vec::new());
    inner_field(&mut inner, 1, &INNER_STREAM_CHACHA20.to_le_bytes());
    inner_field(&mut inner, 2, &inner_key[..]);
    inner_field(&mut inner, 0, &[]);
    let inner_hash = Zeroizing::new(Sha512::digest(&inner_key[..]));
    let mut protect = ChaCha20::new(inner_hash[..32].into(), inner_hash[32..44].into());
    inner.extend_from_slice(xml(name, entries, &mut protect)?.as_bytes());

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&inner).map_err(|e| e.to_string())?;
    let mut payload = gz.finish().map_err(|e| e.to_string())?;
    ChaCha20::new(cipher_key.as_slice().into(), (&iv).into()).apply_keystream(&mut payload);

    let blocks = payload.chunks(BLOCK_SIZE).chain(std::iter::once(&[][..]));
    for (i, block) in blocks.enumerate() {
        let i = i as u64;
        let len = (block.len() as u32).to_le_bytes();
        out.extend_from_slice(&hmac256(&block_key(i, &hmac_key)[..], &[&i.to_le_bytes(), &len, block]));
        out.extend_from_slice(&len);
        out.extend_from_slice(block);
    }
    Ok(out)
}

fn field(out: &mut Vec<u8>, id: u8, data: &[u8]) {
    out.push(id);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn inner_field(out: &mut Vec<u8>, id: u8, data: &[u8]) {
    field(out, id, data)
}

fn variant(out: &mut Vec<u8>, ty: u8, name: &str, value: &[u8]) {
    out.push(ty);
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn block_key(index: u64, hmac_key: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut k = Zeroizing::new([0u8; 64]);
    k.copy_from_slice(&Sha512::new().chain_update(index.to_le_bytes()).chain_update(hmac_key).finalize());
    k
}

fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn escape(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if c.is_control() => return Err("text contains control characters".into()),
            c => out.push(c),
        }
    }
    Ok(out)
}

fn random_uuid() -> String {
    let mut u = [0u8; 16];
    OsRng.fill_bytes(&mut u);
    b64(&u)
}

fn xml(name: &str, entries: &[Entry], protect: &mut ChaCha20) -> Result<Zeroizing<String>, String> {
    let mut x = Zeroizing::new(String::new());
    let s = |x: &mut String, key: &str, value: &str| -> Result<(), String> {
        x.push_str(&format!("<String><Key>{key}</Key><Value>{}</Value></String>", escape(value)?));
        Ok(())
    };
    x.push_str("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile><Meta>");
    x.push_str(&format!("<Generator>Zigner</Generator><DatabaseName>{}</DatabaseName>", escape(name)?));
    x.push_str("</Meta><Root><Group>");
    x.push_str(&format!("<UUID>{}</UUID><Name>{}</Name>", random_uuid(), escape(name)?));
    for e in entries {
        x.push_str(&format!("<Entry><UUID>{}</UUID>", random_uuid()));
        s(&mut x, "Title", &e.title)?;
        s(&mut x, "UserName", &e.username)?;
        s(&mut x, "URL", &e.url)?;
        s(&mut x, "Notes", &e.notes)?;
        let mut protected = |x: &mut String, key: &str, value: &str| {
            let mut v = Zeroizing::new(value.as_bytes().to_vec());
            protect.apply_keystream(&mut v);
            x.push_str(&format!("<String><Key>{key}</Key><Value Protected=\"True\">{}</Value></String>", b64(&v)));
        };
        protected(&mut x, "Password", e.password.as_deref().map_or("", |p| p.as_str()));
        if let Some(otp) = &e.otp {
            protected(&mut x, "otp", otp);
        }
        x.push_str("</Entry>");
    }
    x.push_str("</Group></Root></KeePassFile>\n");
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    const FAST: Kdf = Kdf { memory_kib: 1024, iterations: 1, parallelism: 1 };

    /// Runs keepassxc-cli on `file`, password on stdin. None if it isn't installed.
    fn cli(file: &std::path::Path, args: &[&str]) -> Option<(bool, String)> {
        let mut child = Command::new("keepassxc-cli")
            .args(&args[..1])
            .arg("-q")
            .args(&args[1..])
            .arg(file)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        child.stdin.take().unwrap().write_all(b"correct horse\n").unwrap();
        let out = child.wait_with_output().unwrap();
        Some((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)))
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("zigner-kdbx-{}-{name}.kdbx", std::process::id()))
    }

    #[test]
    fn structure() {
        let db = write("Zigner", &[], "pw", FAST).unwrap();
        assert_eq!(&db[..12], &[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0, 0, 4, 0]);
        assert!(write("Zigner", &[], "", FAST).is_err());
        assert!(escape("a\u{1}b").is_err());
        assert_eq!(escape("<a & 'b'>").unwrap(), "&lt;a &amp; &apos;b&apos;&gt;");
    }

    /// The oracle: KeePassXC must open what Zigner writes.
    #[test]
    fn keepassxc_opens_it() {
        let totp = crate::totp::Account::from_uri(
            "otpauth://totp/GitHub:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub",
        )
        .unwrap();
        let entries = [
            Entry {
                title: "GitHub".into(),
                username: "alice".into(),
                url: "https://github.com".into(),
                password: Some(Zeroizing::new("Brain-Yard-Idle-Ethics-Aunt1".into())),
                otp: Some(totp.to_uri()),
                notes: "derived by Zigner <v1> & such".into(),
            },
            Entry { title: "Bank".into(), username: "".into(), password: Some(Zeroizing::new("088441265327".into())), ..Default::default() },
        ];
        let path = tmp("oracle");
        std::fs::write(&path, write("Zigner backup", &entries, "correct horse", FAST).unwrap()).unwrap();

        let Some((ok, info)) = cli(&path, &["db-info"]) else {
            eprintln!("keepassxc-cli not installed; skipping");
            return;
        };
        assert!(ok, "db-info: {}", info);
        assert!(info.contains("ChaCha20") && info.contains("Argon2id"), "{}", info);

        let (ok, ls) = cli(&path, &["ls"]).unwrap();
        assert!(ok && ls.contains("GitHub") && ls.contains("Bank"), "ls: {}", ls);

        let (ok, pw) = run_show(&path, "GitHub", &["-a", "Password"]);
        assert!(ok && pw.trim() == "Brain-Yard-Idle-Ethics-Aunt1", "password: {}", pw);
        let (ok, notes) = run_show(&path, "GitHub", &["-a", "Notes"]);
        assert!(ok && notes.trim() == "derived by Zigner <v1> & such", "notes: {}", notes);
        let (ok, bank) = run_show(&path, "Bank", &["-a", "Password"]);
        assert!(ok && bank.trim() == "088441265327", "second protected value: {}", bank);

        // Same TOTP code as Zigner computes, at the same moment.
        let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let before = totp.code_at(now());
        let (ok, code) = run_show(&path, "GitHub", &["--totp"]);
        let after = totp.code_at(now());
        assert!(ok, "totp: {}", code);
        assert!(code.trim() == before || code.trim() == after, "keepassxc {} vs zigner {before}", code.trim());

        // Wrong password is refused.
        let mut child = Command::new("keepassxc-cli")
            .args(["ls", "-q"])
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"wrong\n").unwrap();
        assert!(!child.wait().unwrap().success());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn vault_export_through_keepassxc() {
        use crate::passwords::{Policy, Profile};
        const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut v = crate::totp::Vault::new();
        v.add(crate::totp::Account::from_uri("otpauth://totp/ssh2fa:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ssh2fa").unwrap()).unwrap();
        v.add_profile(Profile::new("github.com", "alice", 1, Policy::default()).unwrap()).unwrap();
        let path = tmp("vault");
        // The real cost parameters, so KeePassXC is checked against what ships.
        std::fs::write(&path, write("Zigner main", &entries_from_vault(&v, SEED).unwrap(), "correct horse", Kdf::default()).unwrap()).unwrap();
        if Command::new("keepassxc-cli").arg("--version").output().is_err() {
            eprintln!("keepassxc-cli not installed; skipping");
            return;
        }
        // The frozen v1 vector, read back out of KeePassXC.
        let (ok, pw) = run_show(&path, "github.com", &["-a", "Password"]);
        assert!(ok && pw.trim() == "Brain-Yard-Idle-Ethics-Aunt1", "{}", pw);
        let (ok, user) = run_show(&path, "github.com", &["-a", "UserName", "-a", "URL"]);
        assert!(ok && user.contains("alice") && user.contains("https://github.com"), "{}", user);
        let (ok, code) = run_show(&path, "ssh2fa (TOTP)", &["--totp"]);
        assert!(ok && code.trim().len() == 6, "{}", code);
        let _ = std::fs::remove_file(&path);
    }

    fn run_show(path: &std::path::Path, entry: &str, args: &[&str]) -> (bool, String) {
        let mut child = Command::new("keepassxc-cli")
            .args(["show", "-q"])
            .args(args)
            .arg(path)
            .arg(entry)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"correct horse\n").unwrap();
        let out = child.wait_with_output().unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
    }
}
