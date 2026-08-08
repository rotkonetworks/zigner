#!/usr/bin/env bash
# bump-version.sh — bump the Zigner app version (Android).
#
# Usage:
#   ./bump-version.sh 0.9.0
#
# The Zigner version lives in EXACTLY ONE place: android/build.gradle,
# the `appVersionName` variable. The Android `versionCode` is *derived*
# automatically at build time from versionName as:  M * 1_000_000 + m * 1_000 + p
# (e.g. "0.8.2" -> 8002) — see the `computeVersionCode()` helper in build.gradle.
# So you only edit appVersionName and versionCode follows — never hand-edit both.
#
# AndroidManifest.xml has NO version fields; Gradle injects versionName/versionCode
# from defaultConfig at package time. No manifest edit is required.
#
# NOTE on iOS: the iOS app (MARKETING_VERSION in PolkadotVault.xcodeproj, currently
# on a separate 7.x lineage) is an independent build and is NOT bumped by this
# script. Bump it separately only if you are shipping an iOS release too.
#
# Completes with a fresh assembly so the built APK carries the new version.
set -euo pipefail

NEW_VERSION="${1:-}"
if [[ -z "$NEW_VERSION" ]]; then
  echo "usage: $0 <new-version>   e.g. $0 0.9.0" >&2
  exit 2
fi
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "error: '$NEW_VERSION' is not a valid three-part semver (e.g. 0.9.0)" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUILD_GRADLE="android/build.gradle"
if [[ ! -f "$BUILD_GRADLE" ]]; then
  echo "ERROR: $BUILD_GRADLE not found — run from the zigner repo root" >&2
  exit 1
fi

echo "zigner: bumping appVersionName -> $NEW_VERSION"
sed -i -E "s/^(def appVersionName = \")[^\"]+(\")$/\1${NEW_VERSION}\2/" "$BUILD_GRADLE"

echo
echo "Verifying:"
grep -n "appVersionName" "$BUILD_GRADLE"

# Compute the derived versionCode for the human to sanity-check.
m="${NEW_VERSION%%.*}"; rest="${NEW_VERSION#*.}"; mi="${rest%%.*}"; p="${rest#*.}"; p="${p%%-*}"
code=$(( m * 1000000 + mi * 1000 + p ))
echo "  -> derived versionCode (computed by gradle): $code"

echo
echo "Assembling debug APK with the new version..."
./gradlew :android:assembleDebug --offline

echo
echo "Done. Install with:"
echo "  adb install -r android/build/outputs/apk/debug/android-debug.apk"
