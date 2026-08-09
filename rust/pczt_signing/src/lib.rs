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
//!
//! COMPACT PCZTs (wallet redaction of cv_net, anchors, ciphertexts, fvk):
//! After parsing, `resolve_fields()` recomputes the redacted fields once so
//! the same verification gates apply to compact and full PCZTs. The sighash
//! is computed once per PCZT and reused for every action, and the spend
//! authorizing key is zeroized after signing.

pub mod envelope;

use envelope::{
    encode_response, parse_request, parse_request_full, EnvelopeError, ResponseMessage, SignRequest,
};
use std::collections::BTreeSet;
// compact-response types (re-exported so the wasm ABI + tests can name them)
pub use envelope::{
    encode_compact_response, parse_compact_response, CompactResponse, CompactResponseMessage,
    SignatureContribution, POOL_IRONWOOD, POOL_ORCHARD,
};
use pczt::roles::signer::Signer;
use pczt::Pczt;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::{MainNetwork, TestNetwork};
use zcash_transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zip32::AccountId;

#[derive(Debug)]
pub enum Error {
    Parse(String),
    Seed(String),
    KeyDerivation(String),
    Sign(String),
}

// The low-level Signer role requires the sign closure's error type to be
// `From` of the bundle re-parse error. Since pczt 0.9 that is a single
// `low_level_signer::OrchardParseError` shared by BOTH the orchard and the
// ironwood entry points - it carries the structural parse failure, the
// unsupported-consensus-branch case, and the "signing closure added, removed
// or reordered actions" guard. All of them map into `Error::Parse`.
impl From<pczt::roles::low_level_signer::OrchardParseError> for Error {
    fn from(e: pczt::roles::low_level_signer::OrchardParseError) -> Self {
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
    /// Always populated: the released `pczt` stack models the Ironwood bundle
    /// unconditionally, so a V5 PCZT simply reports 0 here.
    pub ironwood_actions: usize,
    /// Number of transparent inputs we will sign.
    pub transparent_inputs: usize,
    /// Recipient outputs visible in the redacted PCZT: (address-or-"shielded", zatoshi).
    pub outputs: Vec<(String, u64)>,
    /// Declared fee in zatoshi, when derivable from the PCZT balance.
    pub fee_zat: Option<u64>,
    /// Set when [`detect_delegation`] recognizes this PCZT as a Zcash voting
    /// delegation authorization (zafu's `build_delegation_pczt`) rather than
    /// a payment. `None` means: display it as an ordinary send/migration,
    /// exactly as before this field existed.
    pub delegation: Option<DelegationSummary>,
}

/// Truthful, conservative facts about a PCZT [`detect_delegation`] has
/// recognized as a voting-delegation authorization, not a payment.
///
/// Only fields provable from data `verify_displayed_summary` has already
/// bound to the sighash are included here. Notably absent: the vote round
/// id, the delegated ZEC amount, and any human-readable round name / hotkey
/// label. Those only exist inside the governance output's encrypted note
/// plaintext (the memo) - see the doc comment on [`detect_delegation`] for
/// exactly why this device cannot read them, and what would need to change
/// on the producer (zafu) side to make that possible without lying.
#[derive(Debug, Clone)]
pub struct DelegationSummary {
    /// Raw 43-byte orchard/ironwood receiver of the single governance
    /// output, hex-encoded. Bound to the note commitment the same way an
    /// ordinary send recipient is (`verify_note_commitment`, run before this
    /// struct is ever constructed) - the UI renders it as a unified address.
    pub hotkey_recipient: String,
}

/// Confirm that the recipient + amount this summary is about to DISPLAY are
/// the ones the transaction actually pays.
///
/// A cold signer's whole value is that the screen cannot lie. An orchard
/// output's `recipient` and `value` are plaintext metadata the wallet supplies
/// purely for this display - nothing in the signing path reads them - so on
/// their own a hostile wallet could show any recipient and any amount while
/// the transaction pays somebody else. What the transaction is bound to is the
/// note commitment `cmx`, which the sighash covers.
/// `Output::verify_note_commitment` recomputes `cmx` from
/// (recipient, value, rho = nf_old, rseed); zafu's `redact_pczt_for_signer`
/// deliberately keeps all of those on the output side, so the check runs on
/// exactly the bytes that cross the airgap.
///
/// The rule: **EVERY output must be proven against its note commitment. There
/// is no skip.**
///
/// The original version of this gate skipped whenever
/// `verify_note_commitment` reported `MissingRecipient` / `MissingValue` /
/// `MissingRandomSeed`, on the theory that a producer withholding a field gets
/// no guarantee but also no false alarm. That made the whole control
/// bypassable by an ATTACKER, not just waived by an honest producer: the
/// signing path never reads the output `rseed` (pczt's low-level signer sets
/// `rseed: None` itself, and the signature is over a sighash that binds the
/// real `cmx`), so a hostile wallet could strip the output `rseed`, set
/// `recipient` and `value` to whatever the victim expected to see, get the
/// device to display those and sign, then reassemble with the true `rseed`.
///
/// An intermediate fix keyed the skip on whether anything was DISPLAYED -
/// refuse an unprovable output that renders a recipient or a non-zero amount,
/// allow one that renders nothing. That escape hatch was itself reachable by a
/// hostile producer: strip `recipient`, `value` AND `rseed` from every output
/// and every one renders as ("orchard:shielded", 0) while the transaction
/// still pays a real amount bound by `cmx`, with a plausible
/// producer-supplied fee alongside. A signer that displays "shielded, 0" and
/// then signs a real payment has failed at its only job.
///
/// So there is no skip. Any output this device cannot prove - for any reason,
/// including a withheld field - is a refusal naming the action index and the
/// reason. zafu's `redact_pczt_for_signer` keeps `recipient`, `value` and
/// `rseed` on every output, dummy/padding actions included, and all of them
/// verify, so an honestly-redacted PCZT is unaffected. A third-party producer
/// that redacts output plaintext is refused - loudly, at summarize time, with
/// the failing action named. That is the correct failure direction: the
/// alternative fails silently, which is how the original bug survived.
///
/// Still a no-op when the bundle cannot be reached at all (unparsable, unknown
/// consensus branch) - those paths make signing fail on their own.
///
/// The second half of this gate covers the FEE. See
/// [`verify_value_balance`] - the displayed fee is derived from each bundle's
/// `value_sum`, which is producer-supplied metadata, and is checked here
/// against the action value commitments so it cannot be a free-form lie.
fn verify_displayed_summary(pczt: &Pczt) -> Result<(), Error> {
    use pczt::roles::verifier::{OrchardError, Verifier};

    fn check(bundle: &orchard::pczt::Bundle) -> Result<(), OrchardError<String>> {
        for (index, action) in bundle.actions().iter().enumerate() {
            match action.output().verify_note_commitment(action.spend()) {
                Ok(()) => {}
                // Not verifiable because the producer withheld a field the
                // check needs. Unconditional refusal - see above.
                Err(
                    e @ (orchard::pczt::VerifyError::MissingRecipient
                    | orchard::pczt::VerifyError::MissingValue
                    | orchard::pczt::VerifyError::MissingRandomSeed),
                ) => {
                    return Err(OrchardError::Custom(format!(
                        "output cannot be proven against its note commitment \
                         (action {index}: {e:?})"
                    )))
                }
                // A PROVEN lie.
                Err(e) => return Err(OrchardError::Verify(e)),
            }
        }
        verify_value_balance(bundle).map_err(OrchardError::Custom)
    }

    match Verifier::new(pczt.clone())
        .with_orchard(check)
        .and_then(|v| v.with_ironwood(check))
    {
        Ok(_) => Ok(()),
        Err(OrchardError::Verify(e)) => Err(Error::Parse(format!(
            "output does not match what it claims to pay ({e:?})"
        ))),
        Err(OrchardError::Custom(reason)) => Err(Error::Parse(format!(
            "{reason} - refusing to display or sign it"
        ))),
        Err(_) => Ok(()),
    }
}

/// Confirm that a bundle's declared `value_sum` - the number the displayed FEE
/// is computed from - matches the action value commitments.
///
/// `value_sum` is plaintext metadata the producer writes into the PCZT.
/// Nothing in the note-commitment check above constrains it, so on its own a
/// hostile wallet could pay the user's expected recipient the expected amount
/// (both now provably displayed) while declaring a `value_sum` that renders a
/// trivial fee, and route the rest of a large spent note to the miner. An
/// inflated fee is fund loss, not a cosmetic error.
///
/// It is provable without any spend-side note plaintext. The IO Finalizer
/// established, and consensus later re-checks via the binding signature:
///
/// ```text
///     sum(cv_net) - ValueCommit(value_sum, 0) == VerificationKey::from(bsk)
/// ```
///
/// `cv_net` is present on every action and is covered by the sighash this
/// device signs; `bsk` survives zafu's redaction (it clears spend note
/// plaintext and the fvk, not the binding key). Forging a `bsk'` for a
/// different `value_sum'` means finding the discrete log of
/// `[value_sum - value_sum']V` in base `R`, so a producer cannot move the
/// declared balance and stay consistent. This is therefore a genuinely
/// independent derivation, not the same metadata re-read by another route.
///
/// A missing `bsk` is a REFUSAL, not a skip - otherwise stripping one field
/// would disable this check exactly the way stripping `rseed` disabled the
/// output check. An action-less bundle (the canonical-empty Ironwood bundle a
/// V5 PCZT carries) has no commitments to check against, so its `value_sum`
/// must be exactly zero; a non-zero one would shift the displayed fee with
/// nothing backing it.
///
/// SCOPE: this binds the orchard and ironwood terms of the fee, which for a
/// shielded-only transaction is the entire fee. The transparent and sapling
/// terms are NOT bound here - see the note on `compute_fee_zat`.
fn verify_value_balance(bundle: &orchard::pczt::Bundle) -> Result<(), String> {
    use orchard::value::{ValueCommitTrapdoor, ValueCommitment};

    if bundle.actions().is_empty() {
        return if *bundle.value_sum() == orchard::value::ValueSum::default() {
            Ok(())
        } else {
            Err(format!(
                "bundle declares a value balance of {:?} but has no actions to back it",
                bundle.value_sum()
            ))
        };
    }

    let bsk = bundle.bsk().as_ref().ok_or_else(|| {
        "declared value balance (the displayed fee) cannot be proven: binding key absent"
            .to_string()
    })?;

    // ValueCommit(v, 0) - the zero trapdoor is not public API, but a 32-byte
    // zero scalar is the same thing.
    let zero_rcv = ValueCommitTrapdoor::from_bytes([0u8; 32])
        .into_option()
        .ok_or_else(|| "zero value-commitment trapdoor".to_string())?;
    let sum_cv: ValueCommitment = bundle.actions().iter().map(|a| a.cv_net()).sum();
    let bvk = (sum_cv - ValueCommitment::derive(*bundle.value_sum(), zero_rcv)).to_bytes();
    let expected: [u8; 32] = (&orchard::primitives::redpallas::VerificationKey::from(bsk)).into();

    if bvk == expected {
        Ok(())
    } else {
        Err(format!(
            "declared value balance {:?} (which the displayed fee is derived from) \
             does not match the action value commitments",
            bundle.value_sum()
        ))
    }
}

/// Recognize a Zcash voting-delegation authorization PCZT (zafu's
/// `build_delegation_pczt` / `build_governance_pczt`, `zcli/crates/zcash-voting`)
/// and, if so, return the facts about it this device can PROVE - never more.
///
/// WHY THIS IS NOT A PAYMENT: a delegation PCZT does not spend the voter's
/// real delegated notes in-band at all. It carries exactly one action in the
/// Ironwood bundle: a synthetic 1-zatoshi "signed note" spend (rho bound to
/// the delegated notes' commitments + the VAN + the vote round id via
/// `governance::compute_rho_binding`, off-PCZT), paired with a zero-value
/// output to the voting hotkey address whose memo carries the human-readable
/// authorization text. The real delegated notes, the VAN, and the governance
/// nullifiers travel to the cosmos voting chain out of band - never in this
/// transaction - so nothing about "which notes, how much delegated weight"
/// is either signed here or displayable from here.
///
/// DETECTION: structural, not content-based. Orchard's default builder
/// (`BundleType::DEFAULT`, which zafu's governance builder uses) pads every
/// bundle to at least 2 actions for indistinguishability, so a delegation
/// PCZT typically carries the one real governance action PLUS one
/// auto-generated dummy padding action - not a single action. The signal
/// that isolates the real one from the padding is `spend_auth_sig`:
/// `IoFinalizer::finalize_io` immediately signs every padding spend with its
/// own freshly-generated `dummy_sk` and clears it, all before the PCZT is
/// ever redacted for the airgap - so by the time this device sees it, the
/// padding action's spend already carries a signature and the real,
/// still-unsigned action is the only one with `spend_auth_sig == None`. That
/// is exactly "the action this device is being asked to sign", which is
/// also the only action whose truthfulness matters here.
///
/// So: this device recognizes a delegation PCZT as zero transparent inputs,
/// no ORCHARD action left unsigned (a legacy send or an orchard->ironwood
/// migration always leaves an orchard spend unsigned; a delegation never
/// touches the orchard bundle), and exactly one IRONWOOD action left
/// unsigned, whose output value is PROVEN zero
/// (`verify_note_commitment` + `verify_value_balance`, already run by the
/// time this function is called). Detecting on this shape - rather than
/// trying to read a "kind" marker or sniff the memo text - means a forger
/// cannot get a real payment mis-displayed as a delegation: satisfying it
/// requires the one action this device signs to be value-locked at zero, and
/// `verify_value_balance` proves the WHOLE bundle's declared value balance
/// against the summed value commitments, so no other action in the same
/// bundle can be smuggling real value past this check either. Worst case of
/// a false-positive "delegation" label is a mislabeled zero-value
/// transaction - never a mislabeled payment.
///
/// WHAT IS DELIBERATELY NOT DISPLAYED, AND WHY: the delegated amount, the
/// vote round id, and the round name/hotkey label all live ONLY inside the
/// governance output's encrypted note plaintext (the memo). Two independent
/// gaps keep this device from reading them today:
///
/// 1. `summarize()` runs before the seed is available (see `sign_redacted_pczt`
///    for where the seed first appears), so the outgoing viewing key needed
///    to decrypt the wallet's own sent note is not derivable here even in
///    principle.
/// 2. Even with the OVK, this specific output is orchard's "restricted
///    builder" shape - a zero-valued output paired with a real
///    external-scope spend - whose `enc_ciphertext` is deliberately
///    randomized (see the `orchard` crate's own doc comment on
///    `pczt::Output::recipient`), so ordinary outgoing-viewing-key recovery
///    does not apply to it either.
/// 3. zafu's `redact_delegation_pczt_for_signer` (zcli
///    `crates/zcash-voting/src/delegate.rs`) does not currently stash the
///    round id / round name / delegated weight in any PCZT proprietary field
///    that survives redaction - only the generic
///    `zcash_client_backend:output_info` key is stripped, so a differently
///    namespaced field WOULD survive, but nothing populates one today.
///
/// So this function reports only the recipient, and reports it exactly the
/// way an ordinary send's recipient is reported. Extending the display with
/// the round / amount / hotkey label requires a producer-side change (add a
/// namespaced proprietary field, e.g. `zafu_voting:round_id`) plus, if that
/// data is meant to be VERIFIED rather than merely displayed, some binding
/// of it to the signed bytes (it is not enough for it to just be present -
/// see the anti-tamper discussion on `verify_displayed_summary`).
fn detect_delegation(pczt: &Pczt) -> Option<DelegationSummary> {
    if !pczt.transparent().inputs().is_empty() {
        return None;
    }
    // Any orchard action still needing a signature rules this out: a
    // delegation PCZT never asks this device to sign an orchard action (see
    // the doc comment above).
    let orchard_needs_signing = pczt
        .orchard()
        .actions()
        .iter()
        .any(|a| a.spend().spend_auth_sig().is_none());
    if orchard_needs_signing {
        return None;
    }
    let mut unsigned_ironwood = pczt
        .ironwood()
        .actions()
        .iter()
        .filter(|a| a.spend().spend_auth_sig().is_none());
    let action = unsigned_ironwood.next()?;
    if unsigned_ironwood.next().is_some() {
        // More than one action still needs this device's signature - not the
        // single-governance-action delegation shape.
        return None;
    }
    let out = action.output();
    // The one fact that matters for safety: this output cannot move value.
    // `verify_displayed_summary` has already proven this against the note
    // commitment before `detect_delegation` is ever reached.
    if *out.value() != Some(0u64) {
        return None;
    }
    let hotkey_recipient = match out.recipient() {
        Some(r) => hex(r),
        // No recipient to show truthfully - do not guess, do not label it a
        // delegation with a blank recipient. Fall through to the ordinary
        // "orchard:shielded / ironwood:shielded" payment-shaped display,
        // which already refuses to invent a recipient too.
        None => return None,
    };
    Some(DelegationSummary { hotkey_recipient })
}

/// Parse a redacted PCZT and produce the confirmation summary.
pub fn summarize(pczt_bytes: &[u8]) -> Result<PcztSummary, Error> {
    let mut pczt = Pczt::parse(pczt_bytes).map_err(|e| Error::Parse(format!("{e:?}")))?;
    // Resolve compact fields (cv_net, cmx, ciphertexts) for a redacted PCZT.
    // This is a no-op for full PCZTs where these fields are already present.
    pczt.resolve_fields()
        .map_err(|e| Error::Parse(format!("resolve fields: {e:?}")))?;
    verify_displayed_summary(&pczt)?;

    let delegation = detect_delegation(&pczt);

    let orchard_actions = pczt.orchard().actions().len();
    let transparent_inputs = pczt.transparent().inputs().len();

    // Output display: transparent outputs carry script + value in the clear;
    // orchard outputs in a redacted PCZT keep value fields the signer role
    // can read for its own balance check but recipient addresses only when
    // the wallet left them present. Anything unreadable renders "shielded".
    let mut outputs = Vec::new();
    for out in pczt.transparent().outputs() {
        outputs.push((
            format!("t-script:{}", hex(out.script_pubkey())),
            *out.value(),
        ));
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

    // Ironwood (NU6.3 / V6): upstream models the new pool as a second
    // orchard-shaped bundle, so display extraction is identical. A V5 PCZT
    // carries the canonical empty Ironwood bundle, so this loop is a no-op
    // there and `ironwood_actions` is 0.
    let ironwood_actions = pczt.ironwood().actions().len();
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
    // Run for EVERY PCZT, not just ironwood-carrying ones. The fee is one of
    // the three things a cold-wallet user must confirm (recipient, amount,
    // fee); rendering it "unknown" on an ordinary orchard send means they
    // cannot confirm it at all, and the ORCHARD send is the release-critical
    // flow. `compute_fee_zat` is already fail-closed - it returns None (still
    // "unknown") whenever the effects cannot be reconstructed or a transparent
    // prevout value is unavailable - so widening the scope can only turn an
    // "unknown" into a correct number, never into a wrong one.
    //
    // This also removes a divergence: the native FFI path
    // (`signer::inspect_zcash_pczt`) has always shown a real fee for V5, so
    // the same PCZT used to display differently depending on which shipped
    // entry point handled it.
    let fee_zat = compute_fee_zat(pczt_bytes);

    Ok(PcztSummary {
        orchard_actions,
        ironwood_actions,
        transparent_inputs,
        outputs,
        fee_zat,
        delegation,
    })
}

/// Recompute the transaction fee from the PCZT's own value balances.
///
/// Returns `None` when the PCZT cannot be turned into effects (e.g. a
/// redaction that dropped a field the extractor needs, or a transparent
/// input whose prevout value we cannot supply). A `None` fee renders as
/// "unknown" on the device rather than a wrong number - fail-closed for the
/// confirmation screen.
///
/// HOW FAR THE DISPLAYED FEE IS TRUSTED (read this before relying on it):
///
/// The fee is the sum of every bundle's declared value balance. Those are
/// plaintext metadata in the PCZT, so the question for each term is whether
/// anything binds it to what will actually be mined.
///
/// * orchard + ironwood: BOUND. `verify_value_balance` (called by
///   `verify_displayed_summary` before any summary is produced) proves each
///   bundle's `value_sum` against `sum(cv_net)` and `bsk`. A producer cannot
///   move these without solving a discrete log. For a shielded-only
///   transaction - the release-critical flow - this is the entire fee, so the
///   displayed fee is trustworthy there.
/// * transparent: NOT bound here. `fee_paid` derives the transparent term
///   from the PCZT's own input/output `value` fields via the prevout closure.
///   Input amounts are covered by the per-input transparent sighash we sign,
///   but this crate does not cross-check them before display.
/// * sapling: NOT bound here. The sapling bundle carries its own `bsk` and the
///   same relation would prove it, but this crate has no sapling display path
///   and no sapling fixture, so nothing checks it.
///
/// So: a PCZT with transparent or sapling components can still display a fee
/// that is partly producer-supplied. An inflated fee is fund loss, not a
/// cosmetic error, so extending the same binding to those bundles is the next
/// step if either becomes a supported flow.
fn compute_fee_zat(pczt_bytes: &[u8]) -> Option<u64> {
    let mut pczt = Pczt::parse(pczt_bytes).ok()?;
    // Resolve compact fields for a redacted PCZT.
    pczt.resolve_fields().ok()?;
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
///
/// Returns the serialized signed PCZT (the wallet runs SpendFinalizer +
/// TransactionExtractor). For the compact signatures-only response the
/// caller needs the finished (unsigned-proof) `Pczt` too, so the real work
/// lives in [`sign_redacted_pczt_inner`].
/// Pure seed derivation behind the hedged nonce (see `hedged_rng`). Split out
/// so the property that matters can actually be tested: identical host bytes
/// must still give different seeds for different messages.
pub(crate) fn hedged_seed(
    ask: &[u8; 32],
    sighash: &[u8; 32],
    label: &str,
    index: usize,
    host: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"zigner-nonce-v1");
    h.update(ask);
    h.update(sighash);
    h.update(label.as_bytes());
    h.update((index as u64).to_le_bytes());
    h.update(host);
    h.finalize().into()
}

pub fn sign_redacted_pczt(
    pczt_bytes: &[u8],
    seed_phrase: &str,
    account: u32,
    mainnet: bool,
) -> Result<Vec<u8>, Error> {
    sign_redacted_pczt_inner(pczt_bytes, seed_phrase, account, mainnet).map(|(bytes, _, _)| bytes)
}

/// Sign every orchard action and transparent input this seed controls.
/// Returns `(serialized_signed_pczt, finished_pczt)`; the finished `Pczt`
/// is what the compact response extracts spend-auth signatures from.
/// `(signed PCZT bytes, parsed signed PCZT, slots that were ALREADY signed on
/// arrival)`. The third element is what makes a compact response report only
/// this device's own contribution - see [`new_contributions`].
type SignedPczt = (Vec<u8>, Pczt, BTreeSet<(u8, u32)>);

fn sign_redacted_pczt_inner(
    pczt_bytes: &[u8],
    seed_phrase: &str,
    account: u32,
    mainnet: bool,
) -> Result<SignedPczt, Error> {
    let mut pczt = Pczt::parse(pczt_bytes).map_err(|e| Error::Parse(format!("{e:?}")))?;
    // Resolve compact fields (cv_net, cmx, ciphertexts) for a redacted PCZT.
    // This is a no-op for full PCZTs where these fields are already present.
    pczt.resolve_fields()
        .map_err(|e| Error::Parse(format!("resolve fields: {e:?}")))?;
    // Refuse to sign anything we would have refused to display. `sign_request`
    // does not re-run `summarize`, so this must be checked here too.
    verify_displayed_summary(&pczt)?;
    reject_duplicate_rks(&pczt)?;

    // Snapshot which slots ALREADY carry a spend-auth signature, so the
    // compact response can report only what this device adds (see
    // `new_contributions`).
    let prior_slots = signed_slots(&pczt);

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

    /// Hedged (synthetic) nonce RNG for spend-auth signing.
    ///
    /// RedPallas spend-auth signing is randomised Schnorr, and inside wasm the
    /// only entropy source is `host_getrandom` - i.e. the kernel. If the host
    /// ever returns the same bytes twice, a plain `OsRng` reuses a nonce, and
    /// a reused nonce across two different sighashes recovers the signing key.
    /// The wallet is a realistic adversary for that: it chooses the
    /// randomizers, so from `s = r + c*(ask + alpha)` with `r` repeated it has
    /// two equations in two unknowns and `ask` falls out. The failure is
    /// silent - the signatures still verify.
    ///
    /// So derive the nonce seed from secret key material and the message
    /// rather than from host entropy alone. Host randomness is still mixed in
    /// (hedged, not purely deterministic), but it is no longer load-bearing:
    /// a constant host RNG still yields distinct nonces per sighash and per
    /// action. Mixing `ask` is what keeps the seed unpredictable - hedging
    /// over public data only would let anyone who knows the sighash
    /// recompute the nonce, which is strictly worse than the bug it fixes.
    fn hedged_rng(
        ask: &[u8; 32],
        sighash: &[u8; 32],
        label: &str,
        index: usize,
    ) -> rand_chacha::ChaCha20Rng {
        use rand_core::{RngCore, SeedableRng};
        let mut host = [0u8; 32];
        // Best effort: a failure here is survivable precisely because the
        // seed does not depend on it for uniqueness.
        let _ = OsRng.try_fill_bytes(&mut host);
        rand_chacha::ChaCha20Rng::from_seed(crate::hedged_seed(ask, sighash, label, index, &host))
    }

    fn sign_actions_with_fvk(
        pczt_ref: &Pczt,
        bundle: &mut orchard::pczt::Bundle,
        fvk: &orchard::keys::FullViewingKey,
        osak: &orchard::keys::SpendAuthorizingKey,
        ask: &[u8; 32],
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
            match action.sign(sighash, osak, hedged_rng(ask, &sighash, label, index)) {
                Ok(()) => {}
                // Foreign / dummy spends: this device does not hold the key, or
                // the action carries no randomizer to sign under. Skip them -
                // "sign what is yours". Matched on the VARIANT, never on a
                // Debug string: an upstream rename must break the build here
                // rather than silently turn a hard error into a skip.
                Err(
                    orchard::pczt::SignerError::WrongSpendAuthorizingKey
                    | orchard::pczt::SignerError::MissingSpendAuthRandomizer,
                ) => {}
                Err(e) => {
                    return Err(Error::Sign(format!("{label} action {index}: {e:?}")));
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
            &ask,
            shielded_sighash,
            "orchard",
        )
    })?;

    // Ironwood spends: identical treatment. On a V5 PCZT the ironwood bundle
    // is empty, so the closure iterates zero actions and the PCZT round-trips
    // through `reserialize()` unchanged.
    let low = low.sign_ironwood_with(|pczt_ref, bundle, _tx_modifiable| {
        sign_actions_with_fvk(
            pczt_ref,
            bundle,
            &orchard_fvk,
            &osak,
            &ask,
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
    // Since pczt 0.9, `serialize` picks the MINIMAL encoding that can carry the
    // content: the v1 encoding whenever the PCZT is v1-representable (V5 tx and
    // canonical-empty ironwood bundle), the v2 encoding otherwise. So a V5
    // signing response still goes back over the QR as v1 bytes - unchanged for
    // every wallet that predates v2 - while a V6 / ironwood response uses v2.
    let bytes = pczt
        .clone()
        .serialize()
        .map_err(|e| Error::Sign(format!("serialize: {e:?}")))?;
    Ok((bytes, pczt, prior_slots))
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

/// Compact responses carry orchard/ironwood spend-auth signatures only
/// (upstream `BatchSignResponse` semantics); transparent inputs cannot be
/// expressed, so a COMPACT request that includes any transparent input is
/// refused here and the wallet must fall back to the full signed-PCZT
/// response types (0x03/0x04). Shielded-only sends and the Ironwood master
/// migration - the flows the compact transport exists for - never hit this.
/// Reject a PCZT that reuses a randomized verification key across actions,
/// in either pool. `rk` plus the shielded sighash is exactly what a spend-auth
/// signature commits to, so two actions sharing an `rk` share a signature:
/// authorizing one authorizes the other. Consensus would reject the duplicate
/// nullifier anyway, but the device should never hand out a signature that is
/// valid for an action the user did not review. Upstream does the same
/// (Keystone PR 2216 / 2218).
fn reject_duplicate_rks(pczt: &Pczt) -> Result<(), Error> {
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    for (label, actions) in [
        ("orchard", pczt.orchard().actions().len()),
        ("ironwood", pczt.ironwood().actions().len()),
    ]
    .iter()
    .map(|(l, _)| *l)
    .zip([pczt.orchard().actions(), pczt.ironwood().actions()])
    {
        for (index, action) in actions.iter().enumerate() {
            let rk: [u8; 32] = *action.spend().rk();
            if !seen.insert(rk) {
                return Err(Error::Parse(format!(
                    "duplicate action rk at {label} action {index} - one signature would \
                     authorize more than one action"
                )));
            }
        }
    }
    Ok(())
}

fn ensure_compact_supported(pczt: &Pczt, i: usize) -> Result<(), RequestError> {
    if !pczt.transparent().inputs().is_empty() {
        return Err(RequestError::Sign(
            i,
            Error::Sign(
                "compact signatures-only response unsupported for a PCZT with transparent \
                 inputs - resend with the full signed-PCZT types (0x03/0x04)"
                    .into(),
            ),
        ));
    }
    Ok(())
}

/// The full device flow after user confirmation: parse the envelope, sign
/// every message, return the response envelope for the wallet's camera.
///
/// A COMPACT request (tx_type 0x05/0x06) gets a signatures-only response
/// (tx_type 0x07/0x08) - see the envelope module docs - which is what makes
/// the Ironwood migration QR return ~20x smaller. A legacy request
/// (0x03/0x04) still gets full signed PCZTs back, byte-for-byte as before.
pub fn sign_request(
    payload: &[u8],
    seed_phrase: &str,
    account: u32,
    mainnet: bool,
) -> Result<Vec<u8>, RequestError> {
    let parsed = parse_request_full(payload).map_err(RequestError::Envelope)?;
    let request = parsed.request;
    let compact = parsed.compact;
    let single = matches!(request, SignRequest::Single(_));
    let batch = matches!(request, SignRequest::Batch(_));

    if compact {
        // A compact batch must not carry the same PCZT twice - upstream
        // rejects duplicate canonical payloads, and a duplicate is never
        // something the user meant to authorize twice. Scoped to the compact
        // path: the legacy 0x03/0x04 contract is already shipped, and a
        // duplicate there is wasteful rather than unsafe (each response still
        // carries its own full signed PCZT).
        let mut seen: BTreeSet<&[u8]> = BTreeSet::new();
        for (i, m) in request.messages().iter().enumerate() {
            if !seen.insert(m.pczt_bytes.as_slice()) {
                return Err(RequestError::Sign(
                    i,
                    Error::Parse("duplicate PCZT in compact batch request".into()),
                ));
            }
        }

        let mut messages = Vec::with_capacity(request.messages().len());
        for (i, m) in request.messages().iter().enumerate() {
            let (_, pczt, prior) =
                sign_redacted_pczt_inner(&m.pczt_bytes, seed_phrase, account, mainnet)
                    .map_err(|e| RequestError::Sign(i, e))?;
            ensure_compact_supported(&pczt, i)?;
            let signatures = new_contributions(&prior, &pczt);
            // Authorizing nothing is not success. Without this a request whose
            // spends all belong to another account comes back as a "signed"
            // response carrying only the signatures the wallet itself shipped.
            if signatures.is_empty() {
                return Err(RequestError::Sign(
                    i,
                    Error::Sign(
                        "this device authorized no action in the request - wrong account, or \
                         the spends belong to another wallet"
                            .into(),
                    ),
                ));
            }
            messages.push(CompactResponseMessage {
                id: m.id.clone(),
                signatures,
            });
        }
        encode_compact_response(&messages, envelope::COMPACT_RESPONSE_VERSION, single)
            .map_err(RequestError::Envelope)
    } else {
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
}

/// Extract the spend-auth signatures this device produced from `pczt`, in the
/// compact wire shape. Uses `pczt`'s own
/// `extract_orchard_spend_auth_signatures` (PR 2602) so the bytes are exactly
/// the upstream `SpendAuthSignature` semantics: (value_pool, action_index,
/// signature:64) for Orchard and Ironwood.
fn all_contributions(pczt: &Pczt) -> Vec<SignatureContribution> {
    use orchard::ValuePool;
    use pczt::roles::signer::extract_orchard_spend_auth_signatures;
    extract_orchard_spend_auth_signatures(pczt)
        .into_iter()
        .map(|s| SignatureContribution {
            pool: match s.value_pool() {
                ValuePool::Orchard => envelope::POOL_ORCHARD,
                ValuePool::Ironwood => envelope::POOL_IRONWOOD,
            },
            action_index: s.action_index() as u32,
            signature: *s.signature(),
        })
        .collect()
}

/// The (pool, action_index) slots that already carry a spend-auth signature.
fn signed_slots(pczt: &Pczt) -> BTreeSet<(u8, u32)> {
    all_contributions(pczt)
        .into_iter()
        .map(|c| (c.pool, c.action_index))
        .collect()
}

/// Signatures THIS DEVICE produced: everything present after signing minus
/// everything that was already there when the request arrived.
///
/// `extract_orchard_spend_auth_signatures` returns every signature in the
/// object, and a request PCZT legitimately arrives carrying some (the builder
/// authorizes dummy/padding actions with their `dummy_sk` before redaction).
/// Returning those unchanged would make a signatures-only response say "the
/// device authorized this" about signatures the wallet supplied itself - so a
/// request we authorized NOTHING in would still come back looking successful.
/// Upstream closes the same hole by refusing request PCZTs that carry
/// signatures at all (Keystone PR 2225); we take the delta, which additionally
/// tolerates the legitimate pre-authorized dummies.
fn new_contributions(before: &BTreeSet<(u8, u32)>, after: &Pczt) -> Vec<SignatureContribution> {
    all_contributions(after)
        .into_iter()
        .filter(|c| !before.contains(&(c.pool, c.action_index)))
        .collect()
}

/// Wallet-side counterpart to a compact device response: apply one returned
/// signature contribution back into the PCZT the wallet retained.
///
/// Uses `pczt`'s own `Signer::apply_orchard_spend_auth_signature` (PR 2602) so
/// device and wallet share the same (value_pool, action_index) addressing, and
/// the signature is verified against the action's randomized verification key
/// before it is stored - a contribution that is not a valid spend-auth
/// signature for its action is REFUSED here, not silently absorbed. The wallet
/// then runs SpendFinalizer + TransactionExtractor as usual.
pub fn apply_signature_contribution(
    pczt: Pczt,
    sig: &SignatureContribution,
) -> Result<Pczt, Error> {
    use orchard::ValuePool;
    use pczt::roles::signer::SpendAuthSignature;
    let pool = match sig.pool {
        envelope::POOL_ORCHARD => ValuePool::Orchard,
        envelope::POOL_IRONWOOD => ValuePool::Ironwood,
        other => return Err(Error::Parse(format!("unknown value pool {other}"))),
    };
    let upstream = SpendAuthSignature::from_parts(pool, sig.action_index as usize, sig.signature);
    let mut signer = Signer::new(pczt).map_err(|e| Error::Sign(format!("{e:?}")))?;
    signer
        .apply_orchard_spend_auth_signature(&upstream)
        .map_err(|e| Error::Sign(format!("{e:?}")))?;
    Ok(signer.finish())
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
                    // A V5 PCZT has no ironwood actions and emits
                    // ironwood_actions=0. `fee` is the canonical fee that
                    // already includes the ironwood value balance (see
                    // compute_fee_zat); "unknown" when not derivable.
                    let ironwood_actions = s.ironwood_actions;
                    let fee = match s.fee_zat {
                        Some(v) => v.to_string(),
                        None => "unknown".to_string(),
                    };
                    // `kind=` is a new, additive head token: existing parsers
                    // split the head on whitespace and match known prefixes,
                    // ignoring anything else, so an old host still parses
                    // actions/ironwood_actions/t_inputs/fee unchanged. A new
                    // host uses `kind=delegation` to render the truthful
                    // "voting delegation authorization" screen instead of a
                    // payment screen - see `detect_delegation` for exactly
                    // what is (recipient) and is not (round/amount/label)
                    // provable, and therefore shown.
                    let kind = if s.delegation.is_some() {
                        "delegation"
                    } else {
                        "payment"
                    };
                    out.extend_from_slice(
                        format!(
                            "actions={} ironwood_actions={} t_inputs={} fee={} kind={}\n{}",
                            s.orchard_actions,
                            ironwood_actions,
                            s.transparent_inputs,
                            fee,
                            kind,
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

#[cfg(test)]
mod hedged_nonce_tests {
    use super::hedged_seed;

    const ASK: [u8; 32] = [7u8; 32];
    /// A host RNG stuck at a constant - the failure this construction exists
    /// to survive.
    const STUCK: [u8; 32] = [0u8; 32];

    #[test]
    fn a_stuck_host_rng_still_gives_distinct_nonces_per_message() {
        let a = hedged_seed(&ASK, &[1u8; 32], "orchard", 0, &STUCK);
        let b = hedged_seed(&ASK, &[2u8; 32], "orchard", 0, &STUCK);
        assert_ne!(
            a, b,
            "same host entropy across two sighashes must not reuse a nonce - \
             that is exactly the case that leaks ask"
        );
    }

    #[test]
    fn a_stuck_host_rng_still_gives_distinct_nonces_per_action_and_pool() {
        let base = hedged_seed(&ASK, &[1u8; 32], "orchard", 0, &STUCK);
        assert_ne!(base, hedged_seed(&ASK, &[1u8; 32], "orchard", 1, &STUCK));
        assert_ne!(base, hedged_seed(&ASK, &[1u8; 32], "ironwood", 0, &STUCK));
    }

    #[test]
    fn the_secret_key_is_bound_in() {
        // Hedging over public data only would let anyone who knows the
        // sighash recompute the nonce.
        let a = hedged_seed(&ASK, &[1u8; 32], "orchard", 0, &STUCK);
        let b = hedged_seed(&[8u8; 32], &[1u8; 32], "orchard", 0, &STUCK);
        assert_ne!(a, b);
    }

    #[test]
    fn host_entropy_still_contributes_when_it_works() {
        let a = hedged_seed(&ASK, &[1u8; 32], "orchard", 0, &[0u8; 32]);
        let b = hedged_seed(&ASK, &[1u8; 32], "orchard", 0, &[9u8; 32]);
        assert_ne!(a, b, "must be hedged, not purely deterministic");
    }
}
