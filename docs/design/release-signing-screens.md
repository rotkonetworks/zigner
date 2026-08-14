# Release-signing device screens (status + spec)

Status (corrected 2026-08-14):

- **Rust core + FFI:** done (`release_signing.rs`, 8 tests).
- **Android screens:** the two Compose screens already exist and are complete -
  `screens/scan/transaction/ReleaseKeyScreen.kt` (pubkey export, slot picker,
  QR + `index:hex`) and `ReleaseSignScreen.kt` (review → sign → signature QR).
  (An earlier note here that "native UI is not built" was wrong - it searched
  `navigator/src`, the Rust state machine, not `android/src`.)
- **Android wiring - ReleaseKey: DONE.** Reachable at Settings → "Release key"
  via a seed-selector wrapper (`screens/settings/releasekey/`), registered in
  `SettingsNavGraph`. Compiles (`:android:compileDebugKotlin`, offline).
- **Android wiring - ReleaseSign: DONE.** The camera (`CameraViewModel`) detects
  a plain-base64 "ZIGM" prefix (cheap gates + authoritative `releaseClassifyRequest`,
  which accepts only an exact prefix - a module *package* is rejected and stays on
  its `ur:zigner-module` path), surfaces it via `ScanScreen.onReleaseSignPrefix`
  → `ScanViewModel.releaseSignPrefix`, and `ScanNavSubgraph` renders a new
  `ReleaseSignIntegratedScreen` (slot picker + seed unlock → the existing
  `ReleaseSignScreen`). Compiles (`:android:compileDebugKotlin`, offline).
- **iOS:** not started (no release-signing anywhere in `ios/`) - and out of scope
  for now (Android is the platform of interest).

Android is functionally complete. Remaining: iOS (deferred), and the operational
prereq that real keys ship baked into an installed APK before any module update.

## What already exists (do not rebuild)

- `rust/signer/src/release_signing.rs` - derive/classify/sign, domain-separated
  (`RELEASE_DOMAIN = "zigner-release"`; the device prepends `manifest::DOMAIN`
  = `"zigner-module-v1"` itself, so a release key is not a signing oracle).
- FFI (`rust/signer/src/signer.udl`), already generated into Kotlin/Swift:
  - `release_signing_pubkey(seed_phrase, index) -> String` (`"index:hex"`).
  - `release_classify_request(prefix: [u8]) -> ReleaseSigningRequest`
    (`{ module_version, min_kernel_version, module_hash_hex, description }`).
  - `release_sign_request(seed_phrase, index, prefix: [u8]) -> String`
    (`"index:sighex"`, signature over `DOMAIN || prefix`).
- Host side: `modpack keygen/sign/prepare/assemble/verify`, and the zafu.pro
  ceremony page (`parseReleaseKey` → `formatReleaseKeyBytes`, `parseSignature` →
  `assemble`) plus a camera QR scanner that reads exactly the two output formats.

## Trust root context

3 slots, 2-of-3: **slot 0 = GitHub/CI software key**, **slots 1 & 2 = two
zigners**. Each zigner derives its key from its *existing* seed - so these
screens operate on the seed the holder already has; there is no new key to
create on-device. Any two slots authorise a release.

---

## Screen 1: Release key (export the pubkey)

Purpose: show this device's release verifying key so it can be collected in the
ceremony page and baked into `RELEASE_KEY_BYTES`.

- **Entry:** Settings → "Release key" (gate behind the same friction as other
  advanced/verifier screens; it is not a daily-use feature).
- **Inputs:** the selected seed; a slot index picker (1 or 2 - slot 0 is CI).
  Index maps to the derivation index passed to `release_signing_pubkey`.
- **Action:** call `release_signing_pubkey(seed, index)`.
- **Render:** the returned `"index:hex"` as (a) selectable monospace text and
  (b) a single static QR (same static-QR renderer the app already uses; the
  string is ~66 chars, one frame, no fountain).
- **Copy:** "Public key - safe to share. Read it into the ceremony page."

No approval step needed: a public key is not secret and signing nothing.

## Screen 2: Release sign (scan prefix → classify → approve → sign)

Purpose: sign a module manifest prefix with this device's release key.

- **Entry:** the main Scan flow, OR a dedicated "Sign release" entry. The
  scanned payload is **base64 of the raw signing prefix** (contract fixed in
  `zafu.pro/src/lib/release.ts` `prefixToQrPayload`: plain base64, NOT UR - the
  prefix is a few hundred bytes). Detect it by trying `release_classify_request`
  on the base64-decoded bytes and routing here on success.
- **Decode:** base64-decode the scanned string to `Vec<u8>` (native base64 is
  fine; no Rust helper needed). Pass the bytes to the FFI.
- **Classify + display (MANDATORY before signing):** call
  `release_classify_request(prefix)` and show, prominently:
  - `module_version`, `min_kernel_version`
  - `module_hash_hex` - grouped 8 chars, like the confirm screens, so the
    holder can compare it against the hash of a build they reproduced. **The UI
    must say the signature only means something if they checked this hash.**
  - `description` (changelog)
- **Approve:** explicit confirm. `release_sign_request` is not itself consent -
  the screen is.
- **Action:** `release_sign_request(seed, index, prefix)`.
- **Render:** the returned `"index:sighex"` as selectable text + a static QR,
  for the ceremony page (or `modpack assemble --sig`). ~130 chars, one frame.

---

## Template to copy

`SignSufficientCrypto` is the same shape (sign a payload with a device key, emit
a QR) and exists on both platforms - clone its structure, swap the call:

- Android:
  - `domain/backend/SignSufficientCryptoInteractor.kt` → a
    `ReleaseSigningInteractor` calling the three FFI fns.
  - `screens/settings/networks/signspecs/view/SufficientCryptoReadyViewModel.kt`
    → view models for the two screens.
  - Follow a `screens/**/ReleaseSubgraph.kt` after the `ScanNavSubgraph.kt`
    pattern for navigation; reuse the existing static-QR component.
- iOS:
  - `PolkadotVaultTests/Models+Generate/MSufficientCryptoReady+Generate.swift`
    and its non-test SwiftUI counterpart → SwiftUI screens with the same calls.

## Navigation wiring (Rust navigator) - optional

The FFI fns are free functions callable directly from native, so these can be
**native-only auxiliary screens** without new `Screen` enum variants (simplest).
If you prefer them in the state machine for back-stack consistency, add
`Screen::ReleaseKey` and `Screen::ReleaseSign(...)` to `screens.rs` and the
transitions in `navstate.rs`, mirroring `SignSufficientCrypto`'s entries - but
this is not required for a working flow.

## Acceptance

1. Screen 1 on device A shows `1:<hex>`; device B shows `2:<hex>`; ceremony page
   scans both + CI's slot-0 pubkey → emits `RELEASE_KEY_BYTES`; that builds into
   an APK. (Kernel fails closed until this APK is installed.)
2. `modpack prepare` → its base64 prefix QR → Screen 2 on one zigner shows the
   right version/hash/changelog → approve → `1:<sig>`.
3. `modpack sign --slot 0` (CI) + the device's `1:<sig>` → `modpack assemble` →
   `modpack verify` returns **accepted**, and the device kernel accepts the
   package. (The host round-trip is already green; this validates the device
   halves produce interchangeable signatures - which `release_signing.rs` tests
   already assert at the crypto level.)
