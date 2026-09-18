#!/usr/bin/env bash
# GitHub-hosted runner setup only. Uses already installed/licensed SDK and NDK;
# installs only pinned open-source build tools into the ephemeral runner.
set -euo pipefail
fail() { echo "jacs-mobile Android CI setup: $*" >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == true && -n "${RUNNER_TEMP:-}" && -n "${GITHUB_ENV:-}" && -n "${GITHUB_PATH:-}" ]] || \
    fail "Run this setup inside GitHub Actions; local prerequisites are documented in README.md."
android_sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
ndk_version=27.3.13750724
[[ -f "$android_sdk/platforms/android-35/android.jar" && -d "$android_sdk/build-tools/35.0.0" ]] || \
    fail "The runner must already provide Android platform 35 and build-tools 35.0.0."
[[ -d "$android_sdk/ndk/$ndk_version/toolchains/llvm" ]] || \
    fail "The runner must already provide NDK $ndk_version; no SDK downloads or license acceptance are performed."
[[ -n "${JAVA_HOME_17_X64:-}" && -x "$JAVA_HOME_17_X64/bin/javac" ]] || \
    fail "The runner must already provide JDK 17 in JAVA_HOME_17_X64."
printf 'JAVA_HOME=%s\nANDROID_HOME=%s\nANDROID_NDK_HOME=%s\n' \
    "$JAVA_HOME_17_X64" "$android_sdk" "$android_sdk/ndk/$ndk_version" >> "$GITHUB_ENV"
printf '%s\n' "$JAVA_HOME_17_X64/bin" >> "$GITHUB_PATH"

# Gradle's upstream checksum: https://gradle.org/release-checksums/#8.9
gradle_archive="$RUNNER_TEMP/jacs-gradle-8.9-bin.zip"
curl --fail --location --retry 3 --connect-timeout 30 --max-time 300 \
    https://services.gradle.org/distributions/gradle-8.9-bin.zip -o "$gradle_archive"
printf '%s  %s\n' d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab \
    "$gradle_archive" | sha256sum --check --strict
unzip -q "$gradle_archive" -d "$RUNNER_TEMP/jacs-gradle"
printf '%s\n' "$RUNNER_TEMP/jacs-gradle/gradle-8.9/bin" >> "$GITHUB_PATH"
cargo install cargo-ndk --version 4.1.2 --locked
