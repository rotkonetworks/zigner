//! Keystone-compatible PCZT signing: the device-side Signer role.
//!
//! Contract (docs/keystone-compat-pczt-signing.md): the wallet ships a
//! *redacted* PCZT over UR; this crate parses it, recomputes what will be
//! signed, exposes a display summary for user confirmation, signs orchard
//! actions (RedPallas spend-auth) and transparent inputs (secp256k1), and
//! returns the full signed PCZT bytes. Proofs and binding signatures are
//! never our job - they live on the wallet side.
//!
//! Trust property this adds over the legacy digest path
//! (`transaction_signing/zcash.rs`): the sighash is recomputed here from
//! the PCZT contents, so a compromised wallet cannot substitute a digest
//! for a different transaction than the one displayed.

pub mod envelope;

use envelope::{
    encode_response, parse_request, EnvelopeError, ResponseMessage, SignRequest,
};
use pczt::roles::signer::Signer;
use pczt::Pczt;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::{MainNetwork, TestNetwork};
use zip32::AccountId;
use zcash_transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};

#[derive(Debug)]
pub enum Error {
    Parse(String),
    Seed(String),
    KeyDerivation(String),
    Sign(String),
}

// The low-level Signer role requires the sign closure's error type to be
// `From<..>` of the pczt rev's bundle re-parse error. The two pinned revs
// differ: the NU6.3 valar fork uses `pczt::orchard::BundleParseError` (which
// also carries the V6 consensus-branch check for the ironwood bundle); the
// default 5333c01b rev uses `orchard::pczt::ParseError` directly. Provide the
// `From` impl the active rev's bound needs. Both map into `Error::Parse`.
#[cfg(zcash_unstable = "nu6.3")]
impl From<pczt::orchard::BundleParseError> for Error {
    fn from(e: pczt::orchard::BundleParseError) -> Self {
        Error::Parse(format!("orchard bundle parse: {e:?}"))
    }
}

#[cfg(not(zcash_unstable = "nu6.3"))]
impl From<orchard::pczt::ParseError> for Error {
    fn from(e: orchard::pczt::ParseError) -> Self {
        Error::Parse(format!("orchard bundle parse: {e:?}"))
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Parse(e) => write!(f, "pczt parse: {e}"),
            Error::Seed(e) => write!(f, "seed: {e}"),
            Error::KeyDerivation(e) => write!(f, "key derivation: {e}"),
            Error::Sign(e) => write!(f, "signing: {e}"),
        }
    }
}

/// What the user confirms on-screen before signing. Everything here is
/// recomputed from the PCZT itself - nothing is trusted from a side channel.
#[derive(Debug, Clone)]
pub struct PcztSummary {
    /// Number of orchard actions we will spend-auth sign.
    pub orchard_actions: usize,
    /// Number of ironwood actions (NU6.3 / V6 pool, orchard-shaped) present.
    /// Only exists when built against a NU6.3-capable stack; the default
    /// 5333c01b-pinned build never sets the cfg and compiles this out.
    #[cfg(zcash_unstable = "nu6.3")]
    pub ironwood_actions: usize,
    /// Number of transparent inputs we will sign.
    pub transparent_inputs: usize,
    /// Recipient outputs visible in the redacted PCZT: (address-or-"shielded", zatoshi).
    pub outputs: Vec<(String, u64)>,
    /// Declared fee in zatoshi, when derivable from the PCZT balance.
    pub fee_zat: Option<u64>,
}

/// Parse a redacted PCZT and produce the confirmation summary.
pub fn summarize(pczt_bytes: &[u8]) -> Result<PcztSummary, Error> {
    let pczt = Pczt::parse(pczt_bytes).map_err(|e| Error::Parse(format!("{e:?}")))?;

    let orchard_actions = pczt.orchard().actions().len();
    let transparent_inputs = pczt.transparent().inputs().len();

    // Output display: transparent outputs carry script + value in the clear;
    // orchard outputs in a redacted PCZT keep value fields the signer role
    // can read for its own balance check but recipient addresses only when
    // the wallet left them present. Anything unreadable renders "shielded".
    let mut outputs = Vec::new();
    for out in pczt.transparent().outputs() {
        outputs.push((format!("t-script:{}", hex(out.script_pubkey())), *out.value()));
    }
    for action in pczt.orchard().actions() {
        let out = action.output();
        let label = match out.recipient() {
            // 43-byte raw orchard receiver; the UI layer renders it as a
            // unified address. Hex here keeps this crate encoding-agnostic.
            Some(r) => format!("orchard:{}", hex(r)),
            None => "orchard:shielded".to_string(),
        };
        match out.value() {
            Some(v) => outputs.push((label, *v)),
            None => outputs.push((label, 0)),
        }
    }

    // Ironwood (NU6.3 / V6): the fork models the new pool as a second
    // orchard-shaped bundle, so display extraction is identical.
    #[cfg(zcash_unstable = "nu6.3")]
    let ironwood_actions = pczt.ironwood().actions().len();
    #[cfg(zcash_unstable = "nu6.3")]
    for action in pczt.ironwood().actions() {
        let out = action.output();
        let label = match out.recipient() {
            Some(r) => format!("ironwood:{}", hex(r)),
            None => "ironwood:shielded".to_string(),
        };
        match out.value() {
            Some(v) => outputs.push((label, *v)),
            None => outputs.push((label, 0)),
        }
    }

    // Fee: reconstruct the transaction effects from the PCZT and let the
    // canonical fee_paid() sum EVERY bundle's value balance - transparent +
    // sapling + orchard + (cfg-gated) ironwood. For a shielded->shielded
    // turnstile migration there are no transparent inputs, so the prevout
    // lookup is never consulted and the fee is exactly
    // -(orchard_value_balance + ironwood_value_balance). Crucially this does
    // NOT omit the ironwood value_sum: an ironwood-blind fee that only saw
    // the orchard side would report ~the entire migrated amount as fee.
    //
    // Effects extraction needs a second parse (into_effects consumes the
    // Pczt); the redacted turnstile PCZT retains every value_sum the
    // computation reads (redaction only clears witnesses/proofs, not the
    // value commitments), so this succeeds on exactly the bytes we display.
    //
    // Gated to the nu6.3 build: it is the ironwood/turnstile path where an
    // omitted ironwood value_sum would understate the fee. The default
    // 5333c01b build keeps its prior behaviour (fee_zat = None) for normal
    // orchard sends and is untouched - per FIX-B "do not touch that path".
    #[cfg(zcash_unstable = "nu6.3")]
    let fee_zat = compute_fee_zat(pczt_bytes);
    #[cfg(not(zcash_unstable = "nu6.3"))]
    let fee_zat = None;

    Ok(PcztSummary {
        orchard_actions,
        #[cfg(zcash_unstable = "nu6.3")]
        ironwood_actions,
        transparent_inputs,
        outputs,
        fee_zat,
    })
}

/// Recompute the transaction fee from the PCZT's own value balances.
///
/// Returns `None` when the PCZT cannot be turned into effects (e.g. a
/// redaction that dropped a field the extractor needs, or a transparent
/// input whose prevout value we cannot supply). A `None` fee renders as
/// "unknown" on the device rather than a wrong number - fail-closed for the
/// confirmation screen.
#[cfg(zcash_unstable = "nu6.3")]
fn compute_fee_zat(pczt_bytes: &[u8]) -> Option<u64> {
    let pczt = Pczt::parse(pczt_bytes).ok()?;
    let effects = pczt.into_effects().ok()?;
    // Transparent inputs carry their own value in the PCZT (transparent.value
    // is public), but fee_paid takes a prevout lookup by outpoint. We have no
    // prevout db on the device; for the turnstile migration there are no
    // transparent inputs so the closure is never called. If a future request
    // does carry transparent inputs, returning None here makes fee_paid bail
    // and we display "unknown" rather than an understated fee.
    let fee: Result<Option<zcash_protocol::value::Zatoshis>, zcash_protocol::value::BalanceError> =
        effects.fee_paid(|_outpoint| Ok(None));
    fee.ok().flatten().map(u64::from)
}

/// Sign every orchard action and transparent input this seed controls.
/// Returns the serialized signed PCZT (the wallet runs SpendFinalizer +
/// TransactionExtractor).
pub fn sign_redacted_pczt(
    pczt_bytes: &[u8],
    seed_phrase: &str,
    account: u32,
    mainnet: bool,
) -> Result<Vec<u8>, Error> {
    let pczt = Pczt::parse(pczt_bytes).map_err(|e| Error::Parse(format!("{e:?}")))?;

    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, seed_phrase)
        .map_err(|e| Error::Seed(e.to_string()))?;
    let seed = mnemonic.to_seed("");

    let account_id =
        AccountId::try_from(account).map_err(|_| Error::KeyDerivation("bad account".into()))?;

    // ZIP-32 m/32'/coin'/account' - same derivation the legacy digest path
    // uses, so keys match what zafu registered at pairing time.
    let usk = if mainnet {
        UnifiedSpendingKey::from_seed(&MainNetwork, &seed, account_id)
    } else {
        UnifiedSpendingKey::from_seed(&TestNetwork, &seed, account_id)
    }
    .map_err(|e| Error::KeyDerivation(format!("{e:?}")))?;

    let n_transparent = pczt.transparent().inputs().len();

    // The spend authorizing key signs orchard/ironwood spends; the full
    // viewing key is reconstructed here so we never need it shipped in the
    // PCZT (R3 viewing-key leak fix - see below).
    let ask = usk.orchard().to_bytes();
    let sk = orchard::keys::SpendingKey::from_bytes(*ask)
        .into_option()
        .ok_or_else(|| Error::KeyDerivation("orchard sk bytes".into()))?;
    let osak = orchard::keys::SpendAuthorizingKey::from(&sk);
    // R3 viewing-key leak fix: the producer now STRIPS the spend `fvk` (the
    // 96-byte orchard FullViewingKey - a viewing-key leak over the untrusted
    // QR transport) from the redacted PCZT. The high-level `Signer` role is
    // therefore unusable for the shielded spends: its `sign_orchard` /
    // `sign_ironwood` hardcode `Spend::verify_nullifier(None)`, which requires
    // the spend `fvk` and does NOT tolerate `MissingFullViewingKey`. We hold
    // the seed, so we reconstruct the fvk from the same USK and drive the
    // low-level Signer role, supplying the fvk to `verify_nullifier(Some(fvk))`
    // ourselves (`fvk_for_validation` returns the caller-supplied fvk when the
    // PCZT's own `fvk` field is absent). The actual `Action::sign` needs only
    // `alpha` and `rk`, never the fvk, so signatures are unaffected.
    let orchard_fvk = orchard::keys::FullViewingKey::from(&sk);

    // The shielded sighash is a function of tx *effects* only (it does not
    // depend on any spend-auth signature), so we compute it once up front from
    // the parsed PCZT and reuse it for every orchard and ironwood spend.
    let shielded_sighash = Signer::new(pczt.clone())
        .map_err(|e| Error::Sign(format!("{e:?}")))?
        .shielded_sighash();

    // Sign the orchard and ironwood spends via the low-level Signer role. Per
    // action: verify the nullifier against the reconstructed fvk (tolerating
    // the redacted note-plaintext fields exactly like the high-level Signer),
    // then apply the spend-auth signature. Foreign / dummy spends whose key we
    // do not hold error with a Wrong/Missing mismatch and are skipped -
    // "sign what is yours".
    use pczt::roles::low_level_signer::Signer as LowLevelSigner;
    use rand_core::OsRng;

    fn sign_actions_with_fvk(
        pczt_ref: &Pczt,
        bundle: &mut orchard::pczt::Bundle,
        fvk: &orchard::keys::FullViewingKey,
        osak: &orchard::keys::SpendAuthorizingKey,
        sighash: [u8; 32],
        label: &str,
    ) -> Result<(), Error> {
        let _ = pczt_ref;
        for (index, action) in bundle.actions_mut().iter_mut().enumerate() {
            // Consistency check with the caller-supplied fvk. Redacted spends
            // (recipient/value/rho/rseed stripped) surface as Missing* and are
            // tolerated, matching the high-level Signer's own mapping.
            match action.spend().verify_nullifier(Some(fvk)) {
                Ok(())
                | Err(
                    orchard::pczt::VerifyError::MissingRecipient
                    | orchard::pczt::VerifyError::MissingValue
                    | orchard::pczt::VerifyError::MissingRho
                    | orchard::pczt::VerifyError::MissingRandomSeed,
                ) => {}
                Err(e) => {
                    // A real mismatch (e.g. WrongFvkForNote / InvalidNullifier)
                    // on a spend we do not own: skip it, do not abort the batch.
                    let _ = e;
                    continue;
                }
            }
            match action.sign(sighash, osak, OsRng) {
                Ok(()) => {}
                Err(e) => {
                    let msg = format!("{e:?}");
                    // WrongSpendAuthorizingKey / MissingSpendAuthRandomizer are
                    // foreign/dummy spends already handled elsewhere - skip.
                    let foreign = msg.contains("Wrong") || msg.contains("Missing");
                    if !foreign {
                        return Err(Error::Sign(format!("{label} action {index}: {msg}")));
                    }
                }
            }
        }
        Ok(())
    }

    let low = LowLevelSigner::new(pczt);
    let low = low.sign_orchard_with(|pczt_ref, bundle, _tx_modifiable| {
        sign_actions_with_fvk(
            pczt_ref,
            bundle,
            &orchard_fvk,
            &osak,
            shielded_sighash,
            "orchard",
        )
    })?;

    #[cfg(zcash_unstable = "nu6.3")]
    let low = low.sign_ironwood_with(|pczt_ref, bundle, _tx_modifiable| {
        sign_actions_with_fvk(
            pczt_ref,
            bundle,
            &orchard_fvk,
            &osak,
            shielded_sighash,
            "ironwood",
        )
    })?;

    let pczt = low.finish();

    // Transparent inputs are signed with the high-level Signer (they need no
    // fvk). Re-parse via the role over the now spend-auth-signed shielded
    // bundles.
    let mut signer = Signer::new(pczt).map_err(|e| Error::Sign(format!("{e:?}")))?;

    // Transparent inputs: this pczt rev keeps bip32_derivation pub(crate),
    // so instead of reading paths we candidate-scan our account's keys on
    // the standard m/44'/133'/account'/{0,1}/{0..20} tree. Input::sign
    // verifies the pubkey against script_pubkey before mutating, so a
    // wrong-key attempt is a clean no-op error - "sign what is yours",
    // bounded at 40 attempts per input.
    if n_transparent > 0 {
        const GAP_LIMIT: u32 = 20;
        let account_key = usk.transparent();
        let mut candidates = Vec::new();
        for change in 0..=1u32 {
            let scope = TransparentKeyScope::custom(change)
                .ok_or_else(|| Error::KeyDerivation("scope".into()))?;
            for child in 0..GAP_LIMIT {
                let child_index = NonHardenedChildIndex::from_index(child)
                    .ok_or_else(|| Error::KeyDerivation("child index".into()))?;
                if let Ok(sk) = account_key.derive_secret_key(scope, child_index) {
                    candidates.push(sk);
                }
            }
        }
        for index in 0..n_transparent {
            for sk in &candidates {
                if signer.sign_transparent(index, sk).is_ok() {
                    break;
                }
            }
        }
    }

    let pczt = signer.finish();
    Ok(pczt.serialize())
}

#[derive(Debug)]
pub enum RequestError {
    Envelope(EnvelopeError),
    Sign(usize, Error),
}

impl core::fmt::Display for RequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RequestError::Envelope(e) => write!(f, "envelope: {e}"),
            RequestError::Sign(i, e) => write!(f, "message {i}: {e}"),
        }
    }
}

/// Summaries for user confirmation, one per message in the request.
pub fn summarize_request(payload: &[u8]) -> Result<Vec<PcztSummary>, RequestError> {
    let request = parse_request(payload).map_err(RequestError::Envelope)?;
    request
        .messages()
        .iter()
        .enumerate()
        .map(|(i, m)| summarize(&m.pczt_bytes).map_err(|e| RequestError::Sign(i, e)))
        .collect()
}

/// The full device flow after user confirmation: parse the envelope, sign
/// every message, return the response envelope for the wallet's camera.
pub fn sign_request(
    payload: &[u8],
    seed_phrase: &str,
    account: u32,
    mainnet: bool,
) -> Result<Vec<u8>, RequestError> {
    let request = parse_request(payload).map_err(RequestError::Envelope)?;
    let batch = matches!(request, SignRequest::Batch(_));
    let mut responses = Vec::with_capacity(request.messages().len());
    for (i, m) in request.messages().iter().enumerate() {
        let signed = sign_redacted_pczt(&m.pczt_bytes, seed_phrase, account, mainnet)
            .map_err(|e| RequestError::Sign(i, e))?;
        responses.push(ResponseMessage {
            id: m.id.clone(),
            digest: envelope::integrity_digest(&signed),
            signed_pczt: signed,
        });
    }
    encode_response(&responses, batch).map_err(RequestError::Envelope)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// wasm module entropy: forwarded to the kernel host. The host links this
/// import to its CSPRNG; without a host (e.g. bare wasm check) it errors
/// closed rather than yielding weak randomness.
#[cfg(target_arch = "wasm32")]
mod wasm_entropy {
    #[link(wasm_import_module = "zigner_host")]
    extern "C" {
        fn host_getrandom(ptr: *mut u8, len: usize) -> i32;
    }

    fn hostrandom(dest: &mut [u8]) -> Result<(), getrandom::Error> {
        let rc = unsafe { host_getrandom(dest.as_mut_ptr(), dest.len()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(getrandom::Error::UNSUPPORTED)
        }
    }

    getrandom::register_custom_getrandom!(hostrandom);
}

/// C ABI for the wasmi kernel. Convention: (ptr,len) in, packed
/// u64 (ptr<<32|len) out; 0 = error (kernel then calls last_error).
/// Seed handling here is transitional - the target host API keeps seeds
/// kernel-side and exposes sign-digest primitives instead; that swap
/// happens with the host-API freeze (docs/update-architecture.md).
#[cfg(target_arch = "wasm32")]
mod wasm_abi {
    use core::cell::RefCell;

    thread_local! {
        static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
    }

    fn pack(v: Vec<u8>) -> u64 {
        let len = v.len() as u64;
        let ptr = v.leak().as_ptr() as u64;
        (ptr << 32) | len
    }

    #[no_mangle]
    pub extern "C" fn zigner_alloc(len: usize) -> *mut u8 {
        let mut v = Vec::with_capacity(len);
        let ptr = v.as_mut_ptr();
        core::mem::forget(v);
        ptr
    }

    #[no_mangle]
    pub extern "C" fn zigner_summarize_request(ptr: *const u8, len: usize) -> u64 {
        let payload = unsafe { core::slice::from_raw_parts(ptr, len) };
        match crate::summarize_request(payload) {
            Ok(summaries) => {
                let mut out = Vec::new();
                for s in summaries {
                    // Summary head ABI. `ironwood_actions` MUST appear so the
                    // device confirmation head reflects a turnstile migration;
                    // an ironwood-blind head (orchard actions only) would let a
                    // migration render as an empty/zero-action transaction. The
                    // default 5333c01b build has no ironwood pool and emits
                    // ironwood_actions=0. `fee` is the canonical fee that
                    // already includes the ironwood value balance (see
                    // compute_fee_zat); "unknown" when not derivable.
                    #[cfg(zcash_unstable = "nu6.3")]
                    let ironwood_actions = s.ironwood_actions;
                    #[cfg(not(zcash_unstable = "nu6.3"))]
                    let ironwood_actions = 0usize;
                    let fee = match s.fee_zat {
                        Some(v) => v.to_string(),
                        None => "unknown".to_string(),
                    };
                    out.extend_from_slice(
                        format!(
                            "actions={} ironwood_actions={} t_inputs={} fee={}\n{}",
                            s.orchard_actions,
                            ironwood_actions,
                            s.transparent_inputs,
                            fee,
                            s.outputs
                                .iter()
                                .map(|(l, v)| format!("{l}={v}"))
                                .collect::<Vec<_>>()
                                .join("\n"),
                        )
                        .as_bytes(),
                    );
                    out.push(0x1e); // record separator
                }
                pack(out)
            }
            Err(e) => {
                LAST_ERROR.with(|le| *le.borrow_mut() = e.to_string());
                0
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn zigner_sign_request(
        ptr: *const u8,
        len: usize,
        seed_ptr: *const u8,
        seed_len: usize,
        account: u32,
        mainnet: u32,
    ) -> u64 {
        let payload = unsafe { core::slice::from_raw_parts(ptr, len) };
        let seed = unsafe { core::slice::from_raw_parts(seed_ptr, seed_len) };
        let Ok(seed_str) = core::str::from_utf8(seed) else {
            LAST_ERROR.with(|le| *le.borrow_mut() = "seed utf8".into());
            return 0;
        };
        match crate::sign_request(payload, seed_str, account, mainnet != 0) {
            Ok(resp) => pack(resp),
            Err(e) => {
                LAST_ERROR.with(|le| *le.borrow_mut() = e.to_string());
                0
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn zigner_last_error() -> u64 {
        LAST_ERROR.with(|le| pack(le.borrow().clone().into_bytes()))
    }
}
