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

    Ok(PcztSummary {
        orchard_actions,
        #[cfg(zcash_unstable = "nu6.3")]
        ironwood_actions,
        transparent_inputs,
        outputs,
        fee_zat: None,
    })
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

    let n_actions = pczt.orchard().actions().len();
    #[cfg(zcash_unstable = "nu6.3")]
    let n_ironwood = pczt.ironwood().actions().len();
    let n_transparent = pczt.transparent().inputs().len();
    let mut signer = Signer::new(pczt).map_err(|e| Error::Sign(format!("{e:?}")))?;

    // The Signer role reads each action's alpha from the PCZT and applies
    // the randomization internally; we supply the spend authorizing key.
    let ask = usk.orchard().to_bytes();
    let sk = orchard::keys::SpendingKey::from_bytes(*ask)
        .into_option()
        .ok_or_else(|| Error::KeyDerivation("orchard sk bytes".into()))?;
    let osak = orchard::keys::SpendAuthorizingKey::from(&sk);

    for index in 0..n_actions {
        // Redacted PCZTs may include actions we don't control (multi-party);
        // per-action failures for foreign spends are tolerated, matching
        // Keystone semantics of "sign what is yours".
        if let Err(e) = signer.sign_orchard(index, &osak) {
            let msg = format!("{e:?}");
            let foreign = msg.contains("Wrong") || msg.contains("Missing");
            if !foreign {
                return Err(Error::Sign(format!("action {index}: {msg}")));
            }
        }
    }

    // Ironwood actions (NU6.3 / V6): same RedPallas spend-auth key material,
    // second bundle. Dummy spends were already signed by the wallet's IO
    // finalizer and error here with a Wrong-key mismatch, which is tolerated
    // exactly like foreign orchard actions above - "sign what is yours".
    #[cfg(zcash_unstable = "nu6.3")]
    for index in 0..n_ironwood {
        if let Err(e) = signer.sign_ironwood(index, &osak) {
            let msg = format!("{e:?}");
            let foreign = msg.contains("Wrong") || msg.contains("Missing");
            if !foreign {
                return Err(Error::Sign(format!("ironwood action {index}: {msg}")));
            }
        }
    }

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
                    out.extend_from_slice(
                        format!(
                            "actions={} t_inputs={}\n{}",
                            s.orchard_actions,
                            s.transparent_inputs,
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
