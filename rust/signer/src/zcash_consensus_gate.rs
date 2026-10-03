//! Native-path twin of `pczt_signing::consensus_gate` (the module path).
//!
//! The two PCZT signers link different `pczt` releases from different
//! workspaces, so the rules are restated here rather than shared - keep them
//! in step. See that module for the reasoning; in short: refuse, before any
//! summary reaches the screen, every PCZT this build cannot verify and fully
//! display, and keep NU7 off on mainnet until its activation BLOCK HEIGHT is
//! compiled in.
//!
//! One rule is stricter here: this path has no display for transparent
//! outputs, so it refuses them. A transparent output's value is covered by the
//! sighash, but a payment the screen never shows is a payment the user never
//! approved. (The module path renders them; route t-address sends there.)

use crate::ErrorDisplayed;
use pczt::Pczt;
use std::convert::TryFrom;

pub const BRANCH_NU5: u32 = 0xc2d6_d0b4;
pub const BRANCH_NU6: u32 = 0xc8e7_1055;
pub const BRANCH_NU6_1: u32 = 0x4dec_4df0;
pub const BRANCH_NU6_2: u32 = 0x5437_f330;
pub const BRANCH_NU6_3: u32 = 0x37a5_165b;
pub const BRANCH_NU7: u32 = 0x7719_0ad9;

/// Mainnet NU7 activation height; `None` until set (scheduled 2026-10-20).
/// Must match `pczt_signing::consensus_gate::MAINNET_NU7_ACTIVATION`.
pub const MAINNET_NU7_ACTIVATION: Option<u32> = None;

const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
const V6_TX_VERSION: u32 = zcash_protocol::constants::V6_TX_VERSION;
const V6_VERSION_GROUP_ID: u32 = zcash_protocol::constants::V6_VERSION_GROUP_ID;

fn refuse(s: impl Into<String>) -> ErrorDisplayed {
    ErrorDisplayed::Str { s: s.into() }
}

fn nu7_supported_by_build() -> bool {
    zcash_protocol::consensus::BranchId::try_from(BRANCH_NU7).is_ok()
}

pub fn check_supported(pczt: &Pczt) -> Result<(), ErrorDisplayed> {
    let g = pczt.global();
    let (version, group) = (*g.tx_version(), *g.version_group_id());
    let branch = *g.consensus_branch_id();

    let is_v5 = version == V5_TX_VERSION && group == V5_VERSION_GROUP_ID;
    let is_v6 = version == V6_TX_VERSION && group == V6_VERSION_GROUP_ID;
    if !is_v5 && !is_v6 {
        return Err(refuse(format!(
            "Unsupported transaction format (version {version}, group {group:#010x}) \
             - refusing to display or sign it"
        )));
    }

    match branch {
        BRANCH_NU5 | BRANCH_NU6 | BRANCH_NU6_1 | BRANCH_NU6_2 if is_v5 => {}
        BRANCH_NU5 | BRANCH_NU6 | BRANCH_NU6_1 | BRANCH_NU6_2 => {
            return Err(refuse(format!(
                "V6 transaction on pre-NU6.3 branch {branch:#010x} - refusing to display or sign it"
            )))
        }
        BRANCH_NU6_3 => {}
        BRANCH_NU7 if nu7_supported_by_build() => {}
        BRANCH_NU7 => {
            return Err(refuse(
                "This is an NU7 transaction and this Zigner build cannot verify NU7 yet \
                 - update Zigner before signing it",
            ))
        }
        other => {
            return Err(refuse(format!(
                "Unsupported consensus branch {other:#010x} - refusing to display or sign it"
            )))
        }
    }

    let sapling = pczt.sapling();
    if !sapling.spends().is_empty() || !sapling.outputs().is_empty() || *sapling.value_sum() != 0 {
        return Err(refuse(
            "Transaction contains a Sapling component, which Zigner cannot display \
             - refusing to sign it",
        ));
    }

    let t_outputs = pczt.transparent().outputs().len();
    if t_outputs != 0 {
        return Err(refuse(format!(
            "Transaction pays {t_outputs} transparent output(s), which this review screen \
             cannot display - refusing to sign it"
        )));
    }

    Ok(())
}

pub fn check_activation(pczt: &Pczt, mainnet: bool) -> Result<(), ErrorDisplayed> {
    if !mainnet {
        return Ok(());
    }
    let g = pczt.global();
    if *g.consensus_branch_id() == BRANCH_NU7 {
        let Some(activation) = MAINNET_NU7_ACTIVATION else {
            return Err(refuse(
                "NU7 is not active on mainnet in this Zigner build - refusing to sign",
            ));
        };
        let expiry = *g.expiry_height();
        if expiry != 0 && expiry < activation {
            return Err(refuse(format!(
                "NU7 transaction expires at height {expiry}, before NU7 activates at \
                 {activation} - it can never be mined; refusing to sign"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The module path (`rust/pczt_signing`, a separate workspace) carries the
    /// same activation constant. Filling in only one of them on activation
    /// day would make the two signers disagree about NU7 on mainnet.
    #[test]
    fn mainnet_nu7_activation_matches_the_module_path() {
        let module = include_str!("../../pczt_signing/src/consensus_gate.rs");
        let line = |src: &str| {
            src.lines()
                .find(|l| l.starts_with("pub const MAINNET_NU7_ACTIVATION"))
                .map(str::trim)
                .map(String::from)
                .expect("constant present")
        };
        assert_eq!(line(module), line(include_str!("zcash_consensus_gate.rs")));
    }
}
