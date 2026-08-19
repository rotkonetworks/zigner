#!/usr/bin/env bash
#
# CI preflight for zigner - runs what the GitHub rust-* + android workflows run,
# so you catch a fmt/clippy/test failure locally instead of via a red-CI email.
#
#     ./ci-preflight.sh            # everything
#     ./ci-preflight.sh --fast     # skip the slow gradle + wasm builds (fmt + clippy + native tests only)
#     SKIP_ANDROID=1 ./ci-preflight.sh
#
# Mirrors: rust-fmt.yml, rust-clippy.yml, rust-test-android.yml,
# rust-test-ironwood.yml, rust-cargo-deny.yml, reusable-android-tests.yml.
# Runs every check even if an earlier one fails, prints a summary, exits
# non-zero if anything failed. Missing optional tools (nextest, cargo-deny)
# are reported as SKIP, not silent passes.

set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

results=()
step() {
  local name="$1"; shift
  printf '\n\033[1m═══ %s ═══\033[0m\n$ %s\n' "$name" "$*"
  if "$@"; then results+=("PASS  $name"); else results+=("FAIL  $name"); fi
}
skip() { results+=("SKIP  $1  ($2)"); printf '\n\033[33m═══ %s (SKIP) ═══\033[0m\n%s\n' "$1" "$2"; }

# --- rust-fmt.yml ---
step "cargo fmt --check" bash -c 'cd rust && cargo fmt --all -- --check'

# --- rust-clippy.yml ---
step "cargo clippy -D warnings" \
  bash -c 'cd rust && cargo clippy --all-targets --all-features --locked -- -D warnings'

# --- rust-test-android.yml: build the protocol module for wasm32 first ---
if [[ $FAST -eq 0 ]]; then
  step "module wasm32 build" bash -c '
    rustup target add wasm32-unknown-unknown >/dev/null 2>&1
    cd rust/pczt_signing && cargo build --target wasm32-unknown-unknown --release --locked'
else
  skip "module wasm32 build" "--fast"
fi

# --- rust-test-android.yml: three feature combos via nextest ---
if command -v cargo-nextest >/dev/null 2>&1; then
  RUN='cargo nextest run --retries 2 --locked'
else
  # nextest not installed - fall back to cargo test (no --retries flag).
  RUN='cargo test --locked'
  printf '\033[33m(cargo-nextest not found - using `cargo test` for the test steps)\033[0m\n'
fi
step "test: default features"           bash -c "cd rust && $RUN"
step "test: --no-default --features active" bash -c "cd rust && $RUN --no-default-features --features active"
step "test: --no-default-features"      bash -c "cd rust && $RUN --no-default-features"

# --- rust-test-ironwood.yml: pczt_signing E2E (loads the wasm artifact) ---
if [[ $FAST -eq 0 ]]; then
  step "ironwood E2E (pczt_signing)" bash -c '
    cd rust/pczt_signing
    cargo build --target wasm32-unknown-unknown --release --locked
    cargo test --release --locked'
else
  skip "ironwood E2E (pczt_signing)" "--fast"
fi

# --- rust-cargo-deny.yml ---
if command -v cargo-deny >/dev/null 2>&1; then
  step "cargo deny" cargo deny --manifest-path ./rust/Cargo.toml check
else
  skip "cargo deny" "cargo-deny not installed (cargo install cargo-deny)"
fi

# --- reusable-android-tests.yml: android unit tests (slow: needs SDK + cargoBuild) ---
if [[ $FAST -eq 1 || "${SKIP_ANDROID:-0}" == "1" ]]; then
  skip "android unit tests" "skipped (--fast or SKIP_ANDROID=1)"
else
  step "android unit tests" ./gradlew :android:testDebugUnitTest --console=plain
fi

printf '\n\033[1m════════ SUMMARY ════════\033[0m\n'
rc=0
for r in "${results[@]}"; do
  case $r in
    PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
    SKIP*) printf '  \033[33m%s\033[0m\n' "$r" ;;
    *)     printf '  \033[31m%s\033[0m\n' "$r"; rc=1 ;;
  esac
done
if [[ $rc -eq 0 ]]; then
  printf '\n\033[32mAll run checks PASS - safe to push. (SKIP = not run locally; CI will still run it.)\033[0m\n'
else
  printf '\n\033[31mSome checks FAILED - fix before pushing (CI would email you).\033[0m\n'
fi
exit $rc
