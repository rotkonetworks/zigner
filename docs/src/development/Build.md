# Build

Zigner builds two native apps from one Rust core. You'll need a current
[Rust](https://www.rust-lang.org/tools/install) toolchain. If `cargo`
complains about missing features, run `rustup update stable`.

The mobile builds do **not** require opencv. Only the desktop dev tool
`qr_reader_pc` pulls it in, and that crate is gated behind its own
target — building the iOS or Android app from the workspace root skips
it entirely.

## Common — Rust core

UniFFI bindings need the `uniffi-bindgen` binary at the project's
exact version:

```
cargo install uniffi_bindgen --version 0.22.0
```

Sanity-check that the workspace builds and tests pass before opening
either platform IDE:

```
cd rust && cargo test --locked
```

## Android

1. Install [Android Studio](https://developer.android.com/studio).
2. Open the project root (`zigner/`) — the Android module is at the
   top level.
3. Install NDK `24.0.8215888` via *File → Project Structure → SDK
   Location → Download Android NDK*.
4. Add the Android Rust targets:
   ```
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   ```
5. (macOS only) set the python interpreter in `local.properties`:
   ```
   rust.pythonCommand=python3
   ```
6. Run the project. Gradle invokes the Rust build first, links the
   resulting `.so` into the APK, runs UniFFI bindgen, then compiles
   and installs the Kotlin app.

For a release build you can also use the workflow from the command
line:

```
./gradlew :android:installDebug   # build + install on the connected device
./gradlew :android:assembleRelease  # produce an unsigned release APK
```

The CI release workflow at `.github/workflows/android-release.yml`
runs on `v*` tag pushes and produces a signed APK plus
`SHA256SUMS` and `SHA256SUMS.sig`.

## iOS

1. Install [Xcode](https://developer.apple.com/xcode/).
2. Build the Rust core first:
   ```
   cd scripts && ./build.sh ios
   ```
3. Open `ios/PolkadotVault.xcodeproj` in Xcode.
4. Run on a real device (simulator's camera support is incomplete).
   On a simulator, turn off WiFi on your Mac to put the simulated
   device into "airplane" mode.

## Releasing (Android)

1. Bump `versionName` in `android/build.gradle`.
2. Merge to master.
3. Tag `v*` (e.g. `v0.4.2`) and push the tag.

The release workflow runs the test job, builds + signs the APK
(v2 + v3 + v4), computes `SHA256SUMS`, signs the checksum file with
the release ssh ed25519 key, and uploads everything to a GitHub
release. Tags containing `-` (e.g. `v1.0.0-rc1`) publish as
pre-releases.

To verify a downloaded APK:

```
sha256sum -c SHA256SUMS
ssh-keygen -Y verify -f allowed_signers -I release@rotko.net -n file -s SHA256SUMS.sig < SHA256SUMS
```

## Mobile development without StrongBox

The full security model assumes StrongBox (Pixel 8+) or Secure Enclave
(iOS). On simulators or older Android devices, Zigner falls back to
software-only key storage and flags itself as INSECURE in Settings.
Don't use a non-secure-element device for actual key custody.
