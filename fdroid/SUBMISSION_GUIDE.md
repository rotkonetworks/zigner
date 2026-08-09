# F-Droid Submission Guide for Zigner

## Pre-Submission: Blocker Resolution

### Step 1: Remove the Committed Wasm Binary

The file `android/src/main/assets/modules/module0.wasm` must be removed from version control:

```bash
cd /steam/rotko/zigner
git rm android/src/main/assets/modules/module0.wasm
mkdir -p android/src/main/assets/modules
echo "*.wasm" >> android/src/main/assets/modules/.gitignore
git add android/src/main/assets/modules/.gitignore
```

### Step 2: Update the Gradle Build

Modify `android/build.gradle` to compile the wasm during the build. Add this to the `preBuild` dependency chain:

```gradle
// In android/build.gradle, modify the preBuild task dependency:
preBuild.dependsOn "cargoBuild","buildDB","buildWasm"

// Add a new task:
task buildWasm(type: Exec) {
    workingDir "${projectDir}/../rust/pczt_signing"
    commandLine 'cargo', 'build', '--target', 'wasm32-unknown-unknown', '--release', '--locked'
    doLast {
        copy {
            from "${projectDir}/../rust/pczt_signing/target/wasm32-unknown-unknown/release/pczt_signing.wasm"
            into "${projectDir}/src/main/assets/modules"
            rename { "module0.wasm" }
        }
    }
}
```

### Step 3: Verify Local Build Works

Test that the app builds successfully locally:

```bash
cd /steam/rotko/zigner/android
./gradlew clean assembleDebug
```

This should:
1. Compile the Rust wasm module
2. Copy it to assets
3. Build the Android app

The first build will take time (wasm compilation is slow). Subsequent builds will be faster due to Rust incremental compilation.

### Step 4: Test in CI

Push the changes to a branch and verify the GitHub Actions workflows still pass:

```bash
git checkout -b fix/fdroid-wasm-build
git commit -am "fix(fdroid): build wasm module at compile time instead of committed binary"
git push origin fix/fdroid-wasm-build
# Check GitHub Actions results
```

---

## Submission to F-Droid

Once the blocker is resolved, follow these steps to submit to the official F-Droid repository.

### Prerequisites

1. GitHub account (zigner is already public on GitHub)
2. GitLab account (F-Droid uses GitLab for fdroiddata)
3. Familiarity with YAML (the metadata format)
4. GPG key (optional but recommended for signing)

### Step 1: Prepare the Metadata File

Use the provided `net.rotko.zigner.yml` as a starting point. Key sections to verify:

```yaml
License: GPL-3.0-only          # ✓ GPL-3 is F-Droid acceptable
RepoType: git                  # ✓ We have a public git repo
Repo: https://github.com/...   # ✓ Public HTTPS URL
Categories:                    # ✓ Choose from F-Droid's category list
  - Security                   # Appropriate for a cold signer
  - Finance                    # Cryptocurrency app
```

### Step 2: Join fdroiddata

1. Go to https://gitlab.com/fdroid/fdroiddata
2. Fork the repository
3. Clone your fork locally:

```bash
git clone https://gitlab.com/YOUR_USERNAME/fdroiddata.git
cd fdroiddata
git remote add upstream https://gitlab.com/fdroid/fdroiddata.git
```

### Step 3: Add Your Metadata

Create the metadata file in the fdroiddata repo:

```bash
cp /steam/rotko/zigner/fdroid/net.rotko.zigner.yml fdroiddata/metadata/net/rotko/zigner.yml
cd fdroiddata
git add metadata/net/rotko/zigner.yml
git commit -m "add Zigner (net.rotko.zigner)"
```

### Step 4: Verify Metadata Locally

The F-Droid project provides tools to validate metadata:

```bash
# If you have fdroid tools installed:
fdroid lint net.rotko.zigner

# Or use their online linter at https://f-droid.org/wiki/Build_Metadata_Reference
```

Check for:
- YAML syntax errors
- Missing required fields
- Unsupported categories
- Invalid URLs

### Step 5: Create a Merge Request

1. Push to your fork:
```bash
git push origin master
```

2. Go to https://gitlab.com/fdroid/fdroiddata/-/merge_requests/new

3. Select:
   - Source branch: `master` (your fork)
   - Target branch: `master` (upstream)
   - Title: `Add Zigner (net.rotko.zigner)`
   - Description:
     ```
     Application: Zigner
     Package ID: net.rotko.zigner
     
     - Air-gapped hardware signer for Zcash and Penumbra
     - GPL-3.0 licensed
     - Rust + Kotlin + WebAssembly
     - No proprietary dependencies
     - See README for build notes
     ```

### Step 6: Respond to Review

F-Droid maintainers will review your metadata. Common feedback:
- Build issues (wasm compilation timeouts)
- Metadata description improvements
- Screenshots (optional but helpful)
- Changelog entries

Address feedback promptly. The review process typically takes 1-4 weeks depending on maintainer availability.

### Step 7: Handle First Build Failure

The first build will likely fail because:
1. F-Droid builders don't have wasm32 target by default
2. The buildDB task may fail if the script needs adjustment
3. ML Kit barcode scanning might require additional dependencies

**Common fixes:**

For wasm32 target not found:
```yaml
  - versionName: '0.9.0'
    versionCode: 9000
    commit: master
    subdir: android
    gradle: yes
    sudo:
      - 'apt-get update'
      - 'apt-get install -y rustup'
      - 'rustup target add wasm32-unknown-unknown'
    prebuild:
      - 'cd ../rust/pczt_signing && cargo build --target wasm32-unknown-unknown --release --locked'
      - 'cp ../rust/pczt_signing/target/wasm32-unknown-unknown/release/pczt_signing.wasm src/main/assets/modules/module0.wasm'
```

For buildDB script issues:
Check if `android/generate_database.sh` runs correctly in the F-Droid environment. May need to adjust paths or add fallbacks.

### Step 8: Reproducibility Verification

Once the build succeeds, F-Droid may ask for:
- Reproducible builds verification
- Build log review
- APK checksum comparison

The Rust toolchain should produce reproducible binaries if:
- Cargo.lock is present ✓
- Release profile is deterministic ✓
- No timestamps in build ✓

### Step 9: Go Live

Once merged, your app will appear in:
- F-Droid repository automatically
- F-Droid client within 24 hours (default cache refresh)
- F-Droid.org website within 1 hour

---

## Build Times and Resource Requirements

**Expected F-Droid build time: 45-90 minutes**

Breakdown:
- Rust NDK setup: 5-10 min
- wasm32 compilation: 15-20 min
- Android gradle build: 20-30 min
- Database generation: 10-15 min

**Resource requirements:**
- Disk space: ~10 GB (NDK, Rust, gradle cache)
- RAM: 4+ GB recommended
- Network: Initial download ~1-2 GB (gradle deps, rust crates)

F-Droid has sufficient resources, but the build will be among the more complex ones in their queue.

---

## Anti-Features

Zigner does not have any F-Droid anti-features:

- ✓ No tracking
- ✓ No ads
- ✓ No proprietary libraries
- ✓ No Google Play Services
- ✓ No Firebase
- ✓ GPL-3.0 licensed (libre)

(Google ML Kit for barcode scanning is open-source and doesn't require Play Services, so it doesn't trigger an AntiFeature flag.)

---

## Maintenance After Submission

### Update Process

When you release a new version:

1. Tag the release in GitHub:
```bash
git tag v1.0.0
git push origin v1.0.0
```

2. Update the metadata in fdroiddata:
```yaml
Builds:
  - versionName: '0.9.0'
    versionCode: 9000
    commit: v0.9.0
    # ... existing build config ...

  - versionName: '1.0.0'
    versionCode: 1000000
    commit: v1.0.0
    # ... build config ...
```

3. Update AutoUpdateMode to detect new releases:
```yaml
AutoUpdateMode: Version  # Automatically detects new git tags
UpdateCheckMode: Tags    # Check GitHub tags for new releases
```

### Important Notes

- Don't force-push to master once F-Droid is building from it
- Keep Cargo.lock committed for reproducibility
- Update dependency versions through cargo normally (don't force old versions)
- Test locally before tagging releases

---

## Troubleshooting Build Failures

### Issue: `wasm32-unknown-unknown` target not found

**Solution:** Ensure the `sudo` step runs before prebuild:
```yaml
sudo:
  - 'rustup target add wasm32-unknown-unknown'
prebuild:
  - 'cd ../rust/pczt_signing && cargo build --target wasm32-unknown-unknown --release --locked'
```

### Issue: Cargo builds fail with "can't find pczt_signing"

**Solution:** The pczt_signing crate is standalone. Make sure the commit includes all Rust crates.

### Issue: APK doesn't include wasm binary

**Solution:** Verify the file copy step:
```bash
cp ../rust/pczt_signing/target/wasm32-unknown-unknown/release/pczt_signing.wasm \
   src/main/assets/modules/module0.wasm
```

The gradle build must happen AFTER the wasm file is copied.

### Issue: ML Kit barcode scanning doesn't work

**Solution:** Google ML Kit models are downloaded at runtime. Ensure network access during build or use offline models (lower accuracy, but F-Droid compatible).

---

## References

- F-Droid Build Metadata Reference: https://f-droid.org/docs/Build_Metadata_Reference/
- F-Droid Inclusion Guide: https://f-droid.org/docs/Inclusion_How-To/
- Parity Signer on F-Droid: https://f-droid.org/packages/io.parity.signer/ (similar Rust+Android project)
- Zigner GitHub: https://github.com/rotkonetworks/zigner

---

## Questions?

Contact F-Droid via:
- Issue tracker: https://github.com/f-droid/fdroidserver/issues
- Forum: https://forum.f-droid.org/
- IRC: #fdroid on irc.libera.chat
