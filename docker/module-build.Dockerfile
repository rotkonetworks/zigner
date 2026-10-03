# Reproducible build environment for android/src/main/assets/modules/module0.wasm
#
# WHY A CONTAINER AND NOT JUST A TOOLCHAIN PIN
#
# The wasm artifact embeds absolute paths from the machine that built it -
# specifically the rustup toolchain directory and the cargo registry path,
# which arrive via std's panic location strings baked into the precompiled
# std rlib. `strip = true` does not remove them, and no --remap-path-prefix
# on our own compiler invocation can either: we never recompile std, so
# those strings are already fixed in the rlib we link against.
#
# Measured, not assumed:
#
#   crate at /steam/rotko/zigner, toolchain dir `stable-…`  -> 8a35d4db…
#   crate at /steam/rotko/zigner, toolchain dir `1.97.0-…`  -> 0895b406…
#   crate at /tmp/…/pathtest,     toolchain dir `1.97.0-…`  -> 0895b406…
#
# Two different crate paths gave identical bytes; the toolchain directory
# changed them. So the crate location is irrelevant and the $HOME-rooted
# paths are everything. If the strings cannot be removed they must be held
# constant, which is what this image does - and it holds constant the next
# such leak too, rather than waiting for someone to discover it as a red CI
# run.
#
# The official rust images already place CARGO_HOME at /usr/local/cargo and
# RUSTUP_HOME at /usr/local/rustup - absolute paths independent of who runs
# the build. That is the property we need, so we inherit it rather than
# invent our own.
#
# WHO USES THIS
#
#   - CI, to verify the committed asset matches source (a tag can otherwise
#     ship a blob unrelated to the published source)
#   - each holder of a release key, to independently rebuild what they are
#     about to sign. Under 2-of-3 that is the difference between three
#     people attesting to something they verified and three people trusting
#     whoever handed them a blob.
#   - a self-hosted F-Droid repo, as the build recipe
#
# PINNED BY DIGEST, NOT TAG
#
# A tag is mutable. `rust:1.97.0-slim-bookworm` can be repushed with a new
# base OS and different registry contents, which would silently change the
# output - the same class of bug as a floating toolchain, wearing a
# different hat. The digest below is the whole point of the file; do not
# relax it to a tag.
# rust:1.97.0-slim-bookworm as of 2026-08-19. Matches the channel in
# rust/pczt_signing/rust-toolchain.toml; keep the two in step.
FROM rust@sha256:6d220bf85c74e842a79da63997af8d2e74455c0b8847d8bb3a5888572334991d

# A dependency compiles C for wasm32 via cc-rs, which needs clang; the slim
# base has no C compiler. (Observed: `error occurred in cc-rs: failed to find
# tool "clang"`. The consuming crate is most likely secp256k1-sys, but that
# was not confirmed - worth identifying, because a C dependency inside the
# spend authorizer is worth knowing about for its own sake.)
#
# PINNED to exact versions, recorded 2026-10-02 from a build that passed
# (and produced identical bytes twice). Debian ships security updates within
# a stable release, so an unpinned `clang-14` can change under the fixed base
# digest and silently change the output. If the archive drops this version
# the image build FAILS here - that is the intended direction: a changed
# compiler is a deliberate edit to this file, never a silent drift.
RUN apt-get update \
	&& apt-get install --no-install-recommends -y \
		clang-14=1:14.0.6-12 \
		libclang-cpp14=1:14.0.6-12 \
		libclang-common-14-dev=1:14.0.6-12 \
		libllvm14=1:14.0.6-12 \
		llvm-14-linker-tools=1:14.0.6-12 \
	&& ln -s /usr/bin/clang-14 /usr/bin/clang \
	&& rm -rf /var/lib/apt/lists/*

# The wasm target is not in the base image.
RUN rustup target add wasm32-unknown-unknown

# Fixed, so the build path is identical regardless of where the repo lives on
# the host. Measurement above says this does not currently affect the output;
# it costs nothing and removes one more way for that to stop being true.
# It is the CRATE directory, not /src: cargo reads .cargo/config.toml from the
# working directory upward, and the module's wasm getrandom backend is set in
# rust/pczt_signing/.cargo/config.toml.
WORKDIR /src/pczt_signing

# Source is mounted read-only at run time and the target directory lives
# inside the container, so a container build can never write into the host
# tree or pick up host build state.
ENV CARGO_TARGET_DIR=/build/target

ENTRYPOINT ["cargo", "build", \
	"--manifest-path", "/src/pczt_signing/Cargo.toml", \
	"--target", "wasm32-unknown-unknown", \
	"--release", "--locked"]
