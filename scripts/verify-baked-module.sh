#!/usr/bin/env bash
#
# Verify that the module0.wasm we ship is a build of the source we publish.
#
# WHY THIS EXISTS
#
# module0.wasm is the PCZT signer - it authorizes spends inside the wasmi
# sandbox. It is committed to git as 2 MB of opcodes, and until this script
# nothing connected those bytes to rust/pczt_signing. A reviewer reading the
# Rust source was not reading what runs on the phone, and no amount of care
# in review would have caught a divergence.
#
# rust/signer/tests/baked_module.rs pins the asset's sha256, which is a
# different property: it notices the asset CHANGING, so a bump to
# BAKED_MODULE_VERSION becomes a decision. It cannot notice the asset
# DIVERGING from its source, because it never builds the source.
#
# This closes that gap by rebuilding and comparing bytes.
#
# REPRODUCIBILITY IS THE MECHANISM, NOT A BONUS
#
# The comparison only works because the build is deterministic, and it is
# deterministic only inside the pinned container: pczt_signing's release
# profile (codegen-units=1, lto=fat, strip=true) removes symbols but NOT the
# absolute rustup/cargo paths std's panic locations embed, so a host build
# differs machine to machine. docker/module-build.Dockerfile holds those
# paths, the toolchain and the C compiler constant. There is no wasm-opt
# step to introduce a second toolchain.
#
# It is also why rust/pczt_signing/rust-toolchain.toml pins the compiler. A
# floating toolchain would turn every rustc release into a spurious failure,
# and the tempting fix for a spurious failure - recommit the blob - is
# exactly the thing this script exists to prevent.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
asset="$repo_root/android/src/main/assets/modules/module0.wasm"

# The comparison MUST use the container build. A host `cargo build` bakes the
# builder's rustup toolchain directory and cargo registry path into the
# artifact, so host builds differ machine to machine while being perfectly
# correct - comparing against one proves nothing except that you are the
# person who built the committed blob.
# Locally, no docker means skip with a message - a contributor without docker
# should not be blocked from running preflight. In CI it must be a hard
# failure: a gate that silently passes when its tooling is missing is worse
# than no gate, because the green tick still gets read as "verified".
if ! command -v docker >/dev/null 2>&1; then
	if [[ "${1:-}" == "--require-docker" ]]; then
		echo "error: docker is required to verify module0.wasm, and is absent." >&2
		echo "       Refusing to report success without having checked." >&2
		exit 1
	fi
	echo "SKIP: docker not available, cannot verify module0.wasm reproducibly." >&2
	echo "      A host cargo build is not byte-comparable - see" >&2
	echo "      docker/module-build.Dockerfile for why." >&2
	exit 0
fi

built="$("$repo_root/scripts/build-module.sh")"
trap 'rm -f "$built"' EXIT

if [[ ! -f "$built" ]]; then
	echo "error: container build produced no artifact" >&2
	exit 1
fi

if cmp -s "$built" "$asset"; then
	echo "module0.wasm matches a build of rust/pczt_signing ($(sha256sum "$asset" | cut -c1-16)…)"
	exit 0
fi

cat >&2 <<EOF

═══════════════════════════════════════════════════════════════════════
module0.wasm does NOT match a build of rust/pczt_signing.

  committed  $(sha256sum "$asset" | cut -d' ' -f1)  ($(stat -c%s "$asset") bytes)
  built      $(sha256sum "$built" | cut -d' ' -f1)  ($(stat -c%s "$built") bytes)

The asset the device loads is not the source in this tree. Either the
source changed without regenerating the asset, or the asset came from
somewhere other than this source.

If you changed rust/pczt_signing, regenerate it FROM THE CONTAINER - a
host cargo build produces a correct but machine-specific binary that
nobody else can reproduce:

    scripts/build-module.sh android/src/main/assets/modules/module0.wasm

then update EXPECTED_SHA256 in rust/signer/tests/baked_module.rs - and
before you do, decide about module_host::BAKED_MODULE_VERSION. If this
asset ships in a release without that bump, every device that has ever
applied a module update will go on shadowing it forever.

If you did NOT change the source, do not "fix" this by recommitting the
blob. A mismatch here means the shipped binary and the published source
disagree, which is the single thing this check exists to catch.
═══════════════════════════════════════════════════════════════════════

EOF
exit 1
