//! What this signer agrees to look at, decided before anything is displayed.
//!
//! A PCZT carries its own consensus branch id, tx version and expiry height.
//! The network - not this device - decides which branch is valid at which
//! height, so the job here is narrower: refuse every PCZT whose contents this
//! build cannot fully verify and render, BEFORE a summary reaches the screen.
//! The display-honesty checks (`verify_displayed_summary`) used to treat "could
//! not verify" as "nothing to object to", which meant a PCZT for a consensus
//! branch the linked `pczt` stack does not know - NU7, until the crates catch
//! up - rendered recipients and amounts nobody had checked. Refusing loudly is
//! the only correct direction for a cold signer.
//!
//! Activation needs no height table here. The device is offline and never
//! learns the chain height, and there is no OTA path to deliver one. It does
//! not need it: every PCZT carries its consensus branch id, the online wallet
//! picks that branch from the current chain height, and the network rejects a
//! transaction whose branch is wrong for the block it would be mined in. So
//! signing an NU7 transaction before activation, or an NU6.3 one after it,
//! yields a transaction that can never be mined - it cannot move funds. What
//! this device must guarantee is narrower: that it can VERIFY the branch it is
//! shown, and that the screen tells the truth about it. NU7 therefore works on
//! every network from its activation block, with no Zigner release needed.
//!
use pczt::Pczt;
use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};

use crate::Error;

// V5-capable branches this build verifies. Older ones are accepted on purpose:
// whether a branch can still be MINED is the network's decision, and a stale
// one only produces a transaction the network rejects. What this gate refuses
// is what the device cannot VERIFY.
pub const BRANCH_NU5: u32 = 0xc2d6_d0b4;
pub const BRANCH_NU6: u32 = 0xc8e7_1055;
pub const BRANCH_NU6_1: u32 = 0x4dec_4df0;
pub const BRANCH_NU6_2: u32 = 0x5437_f330;
/// NU6.3 "Ironwood" (active on mainnet since height 3,428,143). First branch
/// with V6 transactions.
pub const BRANCH_NU6_3: u32 = 0x37a5_165b;
/// NU7 (ZIP 259). Zebra `network_upgrade.rs` and librustzcash main agree.
pub const BRANCH_NU7: u32 = 0x7719_0ad9;

const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;

/// Whether the linked zcash stack can parse/sighash an NU7 PCZT. Checked
/// rather than assumed, so bumping the crates is what flips it.
fn nu7_supported_by_build() -> bool {
    zcash_protocol::consensus::BranchId::try_from(BRANCH_NU7).is_ok()
}

/// Rules that hold on every network. Run by `summarize` (which does not know
/// the network) and again by signing.
pub fn check_supported(pczt: &Pczt) -> Result<(), Error> {
    let g = pczt.global();
    let (version, group) = (*g.tx_version(), *g.version_group_id());
    let branch = *g.consensus_branch_id();

    let is_v5 = version == V5_TX_VERSION && group == V5_VERSION_GROUP_ID;
    let is_v6 = version == V6_TX_VERSION && group == V6_VERSION_GROUP_ID;
    if !is_v5 && !is_v6 {
        return Err(Error::Parse(format!(
            "unsupported transaction format (version {version}, group {group:#010x}) \
             - refusing to display or sign it"
        )));
    }

    match branch {
        BRANCH_NU5 | BRANCH_NU6 | BRANCH_NU6_1 | BRANCH_NU6_2 if is_v5 => {}
        BRANCH_NU5 | BRANCH_NU6 | BRANCH_NU6_1 | BRANCH_NU6_2 => {
            return Err(Error::Parse(format!(
                "V6 transaction on pre-NU6.3 branch {branch:#010x} - refusing to display or sign it"
            )))
        }
        BRANCH_NU6_3 => {}
        BRANCH_NU7 if nu7_supported_by_build() => {}
        BRANCH_NU7 => {
            return Err(Error::Parse(
                "this is an NU7 transaction and this Zigner build cannot verify NU7 yet \
                 - update Zigner before signing it"
                    .into(),
            ))
        }
        other => {
            return Err(Error::Parse(format!(
                "unsupported consensus branch {other:#010x} - refusing to display or sign it"
            )))
        }
    }

    // Zigner holds no Sapling keys and has no Sapling display path. A Sapling
    // output is a payment nothing here can show; a Sapling value_sum shifts
    // the displayed fee with nothing binding it. Refuse any Sapling component.
    let sapling = pczt.sapling();
    if !sapling.spends().is_empty() || !sapling.outputs().is_empty() || *sapling.value_sum() != 0 {
        return Err(Error::Parse(
            "transaction contains a Sapling component, which Zigner cannot display \
             - refusing to sign it"
                .into(),
        ));
    }

    Ok(())
}
