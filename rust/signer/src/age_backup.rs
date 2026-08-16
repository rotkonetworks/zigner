// age_backup.rs — encrypt a backup to public keys instead of to a passphrase.
//
// The FROST share envelope (frost_backup.rs) is already encrypted, under a
// PBKDF2 passphrase. This is a second option for the same bytes, and it
// changes what you must not lose rather than how strong the cipher is.
//
// A passphrase is a SEPARATE secret. Forgetting it is one of the commonest
// ways a backup turns out to be worthless, and it fails silently - you find
// out at restore time, which is the worst moment to find anything out.
//
// Encrypting to this device's derived SSH key instead makes the ability to
// open the backup seed-derived, like every other key here. The share itself
// still cannot be regenerated from the seed - FROST shares come out of the DKG
// with their own entropy, and that is the property that makes a threshold
// worth having - but the 24 words you already back up now open the envelope,
// so there is one fewer secret to lose.
//
// MULTIPLE RECIPIENTS, deliberately. Encrypting only to the device key ties
// the backup's fate to the seed's: lose the seed and you lose both, which is
// the correlated failure a threshold exists to avoid. Add a co-signer's key,
// or a second device's, and the two can fail independently.
//
// Recipients are ordinary `ssh-ed25519 AAAA...` lines - the same thing the
// device shows on its Release/SSH key screen, and the same thing anyone
// publishes on GitHub - or native `age1...` recipients.

use std::io::{Read, Write};
use std::str::FromStr;

use crate::auth::derive_domain_seed;

/// Own domain, NOT the zigner-ssh or ZID key.
///
/// Both of those exist to SIGN, and the ZID key signs challenges chosen by
/// whatever site asked for one. age's ssh recipients work by mapping an
/// ed25519 key onto X25519, so pointing one at this would make a single
/// keypair both a signing oracle for attacker-chosen input and a decryption
/// key - the sort of cross-protocol reuse that is hard to reason about and
/// unnecessary here.
///
/// Unnecessary because this recipient is self-addressed: no counterparty has
/// to know it in advance, so a dedicated key costs nothing. Co-signers still
/// paste their ordinary ssh public keys, which is their call to make and the
/// normal way age is used.
pub const AGE_BACKUP_DOMAIN: &str = "zigner-backup-age";

/// Parse one recipient string, accepting either flavour.
///
/// Both are tried rather than dispatched on a prefix: "starts with ssh-" would
/// quietly reject ssh-rsa, and guessing wrong produces a confusing error about
/// the wrong format instead of about the actual input.
fn parse_recipient(s: &str) -> Result<Box<dyn age::Recipient + Send>, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty recipient".into());
    }
    if let Ok(r) = age::ssh::Recipient::from_str(t) {
        return Ok(Box::new(r));
    }
    if let Ok(r) = age::x25519::Recipient::from_str(t) {
        return Ok(Box::new(r));
    }
    Err(format!(
        "not a usable recipient: expected an ssh public key line or an age1... recipient, got \"{}\"",
        t.chars().take(24).collect::<String>()
    ))
}

/// Encrypt `plaintext` to every recipient. ASCII-armored, so it survives being
/// pasted into a message or a text file.
pub fn encrypt_to_recipients(plaintext: &[u8], recipients: &[String]) -> Result<String, String> {
    if recipients.is_empty() {
        // Encrypting to nobody produces a file nobody can open. Better to
        // refuse than to hand back something that looks like a backup.
        return Err("no recipients: the result would be undecryptable by anyone".into());
    }
    let parsed: Vec<Box<dyn age::Recipient + Send>> = recipients
        .iter()
        .map(|r| parse_recipient(r))
        .collect::<Result<_, _>>()?;

    let encryptor =
        age::Encryptor::with_recipients(parsed.iter().map(|r| r.as_ref() as &dyn age::Recipient))
            .map_err(|e| format!("age encryptor: {e}"))?;

    let mut armored = Vec::new();
    let writer = age::armor::ArmoredWriter::wrap_output(&mut armored, age::armor::Format::AsciiArmor)
        .map_err(|e| format!("armor: {e}"))?;
    let mut w = encryptor
        .wrap_output(writer)
        .map_err(|e| format!("age encrypt: {e}"))?;
    w.write_all(plaintext).map_err(|e| format!("age write: {e}"))?;
    w.finish()
        .map_err(|e| format!("age finish: {e}"))?
        .finish()
        .map_err(|e| format!("armor finish: {e}"))?;

    String::from_utf8(armored).map_err(|e| format!("armor utf8: {e}"))
}

/// The device's backup keypair, in the shape ssh-key uses.
fn device_keypair(
    seed_phrase: &str,
    index: u32,
) -> Result<ssh_key::private::Ed25519Keypair, String> {
    let seed = derive_domain_seed(seed_phrase, AGE_BACKUP_DOMAIN, index)?;
    Ok(ssh_key::private::Ed25519Keypair::from_seed(&seed))
}

/// This device's recipient as an `ssh-ed25519 ...` line — what to hand out so
/// a backup can be addressed back to this device.
pub fn device_recipient(seed_phrase: &str, index: u32) -> Result<String, String> {
    let keypair = device_keypair(seed_phrase, index)?;
    ssh_key::PublicKey::from(keypair.public)
        .to_openssh()
        .map_err(|e| format!("openssh public encode: {e}"))
}

/// Rebuild this device's SSH key as an OpenSSH private key file.
///
/// age's ssh identity reads a key file, and the device holds a derived seed.
/// The conversion is a formatting step and nothing more - the same key either
/// way - but it means the private half exists in a second representation for
/// the life of this call, so it is built here and dropped here rather than
/// handed to a caller.
fn device_identity(seed_phrase: &str, index: u32) -> Result<age::ssh::Identity, String> {
    let keypair = device_keypair(seed_phrase, index)?;
    let pem = ssh_key::PrivateKey::from(keypair)
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| format!("openssh encode: {e}"))?;
    age::ssh::Identity::from_buffer(pem.as_bytes(), None)
        .map_err(|e| format!("age ssh identity: {e}"))
}

/// Decrypt an armored age file addressed to this device.
pub fn decrypt_with_device_key(
    seed_phrase: &str,
    index: u32,
    armored: &str,
) -> Result<Vec<u8>, String> {
    let identity = device_identity(seed_phrase, index)?;
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(armored.as_bytes()))
        .map_err(|e| format!("age decryptor: {e}"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| {
            format!("age decrypt failed - is this file addressed to this device's key? ({e})")
        })?;
    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|e| format!("age read: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
    const SEED_B: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    #[test]
    fn round_trips_to_this_device() {
        let recipient = device_recipient(SEED_A, 0).unwrap();
        assert!(recipient.starts_with("ssh-ed25519 "));
        let armored = encrypt_to_recipients(b"share envelope bytes", &[recipient]).unwrap();
        assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        let out = decrypt_with_device_key(SEED_A, 0, &armored).unwrap();
        assert_eq!(out, b"share envelope bytes");
    }

    /// The point of multiple recipients: either holder can open it, alone.
    #[test]
    fn either_recipient_can_open_it() {
        let a = device_recipient(SEED_A, 0).unwrap();
        let b = device_recipient(SEED_B, 0).unwrap();
        let armored = encrypt_to_recipients(b"two holders", &[a, b]).unwrap();
        assert_eq!(decrypt_with_device_key(SEED_A, 0, &armored).unwrap(), b"two holders");
        assert_eq!(decrypt_with_device_key(SEED_B, 0, &armored).unwrap(), b"two holders");
    }

    /// A device that is not a recipient must not be able to read it, which is
    /// the whole claim being made.
    #[test]
    fn a_device_not_addressed_cannot_open_it() {
        let a = device_recipient(SEED_A, 0).unwrap();
        let armored = encrypt_to_recipients(b"only for A", &[a]).unwrap();
        assert!(decrypt_with_device_key(SEED_B, 0, &armored).is_err());
    }

    /// Different derivation index is a different key, so it is a different
    /// recipient - worth pinning, since the index is easy to pass wrongly.
    #[test]
    fn a_different_index_is_a_different_recipient() {
        let a0 = device_recipient(SEED_A, 0).unwrap();
        let a1 = device_recipient(SEED_A, 1).unwrap();
        assert_ne!(a0, a1);
        let armored = encrypt_to_recipients(b"index zero", &[a0]).unwrap();
        assert!(decrypt_with_device_key(SEED_A, 1, &armored).is_err());
    }

    #[test]
    fn refuses_to_encrypt_to_nobody() {
        assert!(encrypt_to_recipients(b"x", &[]).is_err());
    }

    #[test]
    fn refuses_a_recipient_it_cannot_parse() {
        let err = encrypt_to_recipients(b"x", &["not-a-key".to_string()]).unwrap_err();
        assert!(err.contains("not a usable recipient"), "unexpected: {}", err);
    }
}
