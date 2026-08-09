//! A forcing function for the baked module asset.
//!
//! `BAKED_MODULE_VERSION` decides whether a module shipped inside an APK can
//! ever take effect: the slot store discards any installed slot that is not
//! strictly newer. Ship a new asset without bumping it and every device that
//! has ever applied a module update keeps shadowing the new one - silently,
//! and precisely on the devices most likely to need the fix.
//!
//! Nothing about changing `module0.wasm` would otherwise remind anyone. This
//! test fails when the asset changes, so the bump becomes a decision rather
//! than something to remember.

use sha2::{Digest, Sha256};

const MODULE: &[u8] = include_bytes!("../../../android/src/main/assets/modules/module0.wasm");

/// sha256 of the asset this tree ships. The build is deterministic - a local
/// rebuild reproduces it byte for byte - so this is a stable pin, not a
/// snapshot of one machine's output.
const EXPECTED_SHA256: &str = "d99abfa8eb30b309609fb88740b24a22415e876f2201584109c200bc05455825";

#[test]
fn baked_module_is_pinned_to_its_recorded_version() {
    let actual = hex::encode(Sha256::digest(MODULE));
    assert_eq!(
        actual,
        EXPECTED_SHA256,
        "\n\nThe baked module0.wasm changed.\n\
         Before updating EXPECTED_SHA256, decide about \
         module_host::BAKED_MODULE_VERSION (currently {}):\n\
         bump it if this asset ships in a release, or a device that already \
         applied a module update will go on shadowing this one forever.\n",
        module_host::BAKED_MODULE_VERSION
    );
}
