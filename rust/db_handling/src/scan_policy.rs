//! What the camera may hand to a parser on this device.
//!
//! The camera is the only untrusted input, and every QR code is classified
//! by its prefix before any parser runs. A parser is reachable only when
//! this device holds something it would be used with: no Penumbra key, no
//! Penumbra parsing; no Zcash key or FROST wallet, no Zcash parsing. The
//! answer is derived from the database every time it is asked, so there is
//! no setting that can drift from what the device holds.
//!
//! Three kinds stay open on an empty device, because they are how a device
//! stops being empty: recovery (banana split and backup import), creating
//! a FROST wallet, and signed module updates.

use definitions::crypto::Encryption;

use crate::identities::{get_all_addresses, has_keys_for};
use crate::Result;

/// Signed protocol-module updates. The signature is checked before use.
pub const MODULE: &str = "module";
/// Seed recovery and backup import.
pub const BACKUP: &str = "backup";
/// FROST key generation, which starts before any FROST wallet exists.
pub const FROST_DKG: &str = "frost-dkg";
/// FROST signing rounds.
pub const FROST: &str = "frost";
/// Zcash notes and PCZT signing requests.
pub const ZCASH: &str = "zcash";
/// Penumbra signing requests.
pub const PENUMBRA: &str = "penumbra";
/// ZID identity challenges, derived from a seed.
pub const AUTH: &str = "auth";

/// The kinds of QR code this device's camera may parse. Polkadot and
/// Cosmos are never in it.
pub fn readable(database: &sled::Db) -> Result<Vec<&'static str>> {
    let has_frost_wallet = !crate::frost::list_frost_wallets(database)?.is_empty();
    let mut out = vec![MODULE, BACKUP, FROST_DKG];
    if has_frost_wallet {
        out.push(FROST);
    }
    if has_frost_wallet || has_keys_for(database, Encryption::Zcash)? {
        out.push(ZCASH);
    }
    if has_keys_for(database, Encryption::Penumbra)? {
        out.push(PENUMBRA);
    }
    if !get_all_addresses(database)?.is_empty() {
        out.push(AUTH);
    }
    Ok(out)
}
