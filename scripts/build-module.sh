#!/usr/bin/env bash
#
# Build module0.wasm reproducibly, in the pinned container.
#
#   scripts/build-module.sh [output-path]
#
# Writes the artifact to output-path (default: a temp file whose location is
# printed). Does NOT touch the committed asset - regenerating that is a
# deliberate act, see scripts/verify-baked-module.sh for what else has to
# change alongside it.
#
# The container exists because the artifact embeds the rustup toolchain and
# cargo registry paths of whoever built it; see docker/module-build.Dockerfile
# for the measurements. A host `cargo build` produces a DIFFERENT binary from
# this one - correct and functional, but not byte-comparable, so it cannot be
# used to verify what anybody signed.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-}"
image="zigner-module-build"

if ! command -v docker >/dev/null 2>&1; then
	echo "error: docker is required for a reproducible module build" >&2
	echo "       (a host cargo build works but is not byte-comparable)" >&2
	exit 2
fi

# Quiet unless something goes wrong: this runs inside preflight, which has its
# own progress output.
docker build \
	--quiet \
	--file "$repo_root/docker/module-build.Dockerfile" \
	--tag "$image" \
	"$repo_root/docker" >/dev/null

# The source is mounted read-only and the target directory lives inside the
# container, so this cannot write into the host tree or pick up host build
# state. Output is retrieved with `docker cp` rather than a bind mount so the
# file lands owned by the invoking user instead of root.
container="zigner-module-build-$$"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

# nice: this is a full cold build of the dependency graph and should not
# compete with whatever else is running on the machine.
nice -n 19 docker run \
	--name "$container" \
	--volume "$repo_root/rust:/src:ro" \
	--cpus 2 \
	"$image" >&2

if [[ -z "$out" ]]; then
	out="$(mktemp -t module0.XXXXXX.wasm)"
fi

docker cp \
	"$container:/build/target/wasm32-unknown-unknown/release/pczt_signing.wasm" \
	"$out" >/dev/null

echo "$out"
