# Zigner update architecture: camera-delivered signed modules

Problem: zafu updates through the store in hours; zigner is permanently
offline. Reinstall-over-USB for every protocol change (Ironwood, future
NUs, new summary renderers) is unacceptable UX. Whatever v1 ships defines
the update trust root forever - devices air-gapped on v1 can only ever be
updated by mechanisms v1 already contains.

## Core idea

Split the firmware:

- **Kernel** (native, rarely changes, updates only via store/USB):
  camera + QR codec + fountain decoder, display, **seed custody and
  raw signing primitives**, the wasm runtime, the update verifier,
  anti-rollback storage, A/B module slots.
- **Protocol module** (wasm, ~1-3 MB, updates over the camera):
  QR envelope parsing, PCZT parsing, **sighash computation (V5 today,
  V6/Ironwood by module update)**, summary construction, network
  parameters.

zafu is the carrier: it ships new zigner modules inside its own store
updates (or fetches them from zigner.rotko.net) and plays them as an
animated QR. Any screen can be the carrier - trust comes from
signatures, not the transport.

Bandwidth reality: animated QR moves ~30-60 KB/s. A full APK (75 MB) is
a 30-minute non-starter; a stripped protocol module (1-3 MB) is a
30-90 second ceremony. The kernel/module split exists to make the
updateable part QR-sized.

## Trust boundary (why a malicious-module is bounded)

The seed NEVER enters wasm. Host API exposed to the module:

    host.sign_orchard(digest32, alpha32, account) -> sig64
    host.sign_transparent(digest32, scope, index, account) -> sig
    host.derive_ovk/fvk(...) -> viewing material only
    host.display(summary_struct)                  // render, don't trust module pixels
    host.confirm() -> bool                        // hardware-side user gate

A compromised-but-correctly-signed module can request signatures over
wrong digests - identical blast radius to a malicious firmware update in
ANY scheme - but can never exfiltrate key material through the QR
response channel because it never holds it. Bugs (not malice) in
protocol logic cannot brick key custody.

Runtime: **wasmi** (pure-Rust interpreter). No JIT, no platform
permissions games, deterministic, links into the existing libsigner.so.
Sighash workloads are microseconds; interpretation cost is irrelevant.

## Update payload

    manifest {
      module_version: u32          // strictly monotonic
      min_kernel_version: u32
      module_hash: sha256
      description: short human text
      signatures: 2-of-3 ed25519 over all of the above
    }
    module: wasm bytes

- **2-of-3 release keys**, generated on separate offline machines. One
  key lost or compromised is survivable; the set is baked into the
  kernel at build time and can only rotate via a kernel (store/USB)
  update.
- **Anti-rollback**: kernel persists the highest installed
  module_version; refuses anything lower or equal. Prevents replaying an
  old vulnerable module at a victim.
- **A/B slots + self-test**: new module lands in the inactive slot; on
  first run the kernel executes a self-test vector (parse + sign a
  fixture PCZT against a known-good signature); failure auto-reverts to
  the previous slot. A bad module can never brick signing.

## Ceremony (user's view)

1. zafu (or zigner.rotko.net) shows "zigner update available - point
   your zigner at the screen".
2. Zigner scans ~60s of animated QR (fountain-coded; missed frames
   don't restart).
3. Device shows: new version, description, hash prefix; user compares
   hash prefix against the one zafu displays; confirms on-device.
4. Verify sigs -> anti-rollback check -> install to inactive slot ->
   self-test -> activate.

## What v1 MUST contain (the unretrofittable list)

1. The 2-of-3 verifier pubkeys.
2. Anti-rollback counter storage.
3. wasmi + the host API surface (frozen carefully - additive-only after
   v1; a module may probe `host.api_version`).
4. A/B module store + self-test harness.
5. Multi-MB fountain QR decode (exists - Vault-fork inheritance + the
   zcli UR work).
6. Module #0: today's pczt_signing logic compiled to wasm, embedded in
   the APK as the initial active module (so the store build works with
   zero scans).

Everything else - V6/Ironwood sighash, migration summaries
("moving X ZEC to the new pool"), batch tweaks, new networks - arrives
as module updates through the camera.

## Non-goals

- Kernel self-update over QR (75 MB problem + verifier updating its own
  trust root; kernel updates stay on the store/USB path and should be
  rare by design).
- Defense against 2-of-3 release-key compromise beyond the threshold
  itself (same trust as any firmware vendor).

## Relationship to Ironwood timing

This inverts the release-blocking question. v1 does NOT need V6 code;
it needs the RUNTIME. Ship v1 with module #0 = V5 PCZT verify + the
digest fallback path; when NU6.3 crates stabilize, the V6-capable
module is a 60-second camera update - "your signer learned the new
pool through its camera" is the launch story, not a recall.

## Build sequencing

1. `pczt_signing` -> wasm32 target check; strip to sighash+parse+sign
   host-call shape (no key derivation in-module; drop bip39/zcash_keys
   from the module build).
2. Kernel: wasmi embed + host API + verifier + slots (Rust, inside
   existing signer crate boundary).
3. Module packer + manifest signer (zcli subcommand; release keys
   offline).
4. zafu: "zigner updates" screen - fetch/bundle module, animated QR
   player (QR encode already exists).
5. Interop test extension: run the interop flow with the module
   executing under wasmi instead of native - same test, same
   assertions.
