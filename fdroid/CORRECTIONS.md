# Corrections to the audit in this directory

The audit was produced by an assistant and two of its load-bearing claims were
checked and found WRONG. They are corrected here; the other documents in this
directory still contain the original wording in places, so read this first.

## 1. ML Kit is proprietary. It is a blocker, and probably the bigger one.

`SUBMISSION_GUIDE.md` states:

> Google ML Kit for barcode scanning is open-source and doesn't require Play
> Services, so it doesn't trigger an AntiFeature flag.

That is false on both counts. `com.google.mlkit:barcode-scanning:17.3.0`
(android/build.gradle:205) is a closed-source Google library shipping
proprietary native binaries in its AAR. F-Droid's inclusion policy requires
all shipped code to be free software, so this fails outright - it is not an
AntiFeature to declare, it is a rejection.

`SUBMISSION_GUIDE.md` also suggests ensuring "network access during build" to
fetch ML Kit models. For an airgapped signer that advice is doubly wrong.

Scope of the fix: only 6 references across 2 files
(screens/scan/camera/CameraView.kt and CameraViewModel.kt), so the change is
contained. But it replaces the single most important input path in the
product, and scan throughput is a real constraint here - animated UR fountain
QR runs at up to ~16 fps, and module transfer times were measured against
that. `zxing-cpp` (Apache-2.0) is the realistic candidate; the legacy pure-Java
zxing is materially slower and would want measuring before committing to it.

## 2. There is no Parity Signer precedent on F-Droid.

Several documents cite Parity Signer as an existing F-Droid app with a similar
Rust+Android build, at https://f-droid.org/packages/io.parity.signer/ .
That URL returns HTTP 404, and a search of f-droid.org finds no such package
under any id. The precedent does not exist and should not be relied on when
estimating how F-Droid will treat our build recipe.

## 3. Invented precision

"Reproducibility: 90-95%", "1-2 person-days", "20-30 min added build time" are
not measurements. Nothing was timed or counted to produce them.

## What the audit got right

- The prebuilt `android/src/main/assets/modules/module0.wasm` really is a
  blocker: F-Droid builds from source and will not ship a binary checked into
  git. It has to be built in the recipe from rust/pczt_signing. Note we already
  know this build is deterministic - a local rebuild reproduces the shipped
  asset byte-for-byte - which helps.
- GPL-3.0 is correct and is F-Droid-acceptable.
- No Firebase, no Play Services.
