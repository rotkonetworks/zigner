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

/// sha256 of the asset this tree ships.
///
/// This pin is a snapshot of ONE ENVIRONMENT's output, not of the source. A
/// host `cargo build` bakes the builder's rustup toolchain directory and
/// cargo registry path into the artifact - via std's panic location strings,
/// which `strip = true` does not remove - so two people building identical
/// source get different bytes. Measured: the same source at two different
/// crate paths produced identical output, while the same path under
/// toolchain dirs `stable-…` and `1.97.0-…` did not.
///
/// `scripts/verify-baked-module.sh` builds in the pinned container from
/// `docker/module-build.Dockerfile`, which holds those paths constant, and
/// compares bytes. That is the check that ties this asset to its source;
/// this test only notices the asset changing, so the
/// `BAKED_MODULE_VERSION` decision below stays a deliberate one.
const EXPECTED_SHA256: &str = "33441a3fa62e6cc6b258860d7bce0f26c1fc943e419fc59298197df50b82e93e";

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
