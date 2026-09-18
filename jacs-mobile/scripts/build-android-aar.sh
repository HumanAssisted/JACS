#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
fail() { echo "jacs-mobile Android build: $*" >&2; exit 1; }
reuse_bindings=false
if [[ "${1:-}" == --reuse-bindings && $# == 1 ]]; then
    reuse_bindings=true
elif [[ $# != 0 ]]; then
    fail "Usage: $0 [--reuse-bindings] (reuse only bindings generated from this checkout)."
fi
for program in cargo rustup java gradle python3; do
    command -v "$program" >/dev/null || fail "Missing $program. Install the documented prerequisites first."
done
cargo ndk --version >/dev/null 2>&1 || fail "Missing cargo-ndk. Install it before running this script."
[[ -n "${ANDROID_NDK_HOME:-}" && -d "$ANDROID_NDK_HOME/toolchains/llvm" ]] || \
    fail "Set ANDROID_NDK_HOME to an installed Android NDK (toolchains/llvm must exist)."
android_sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
[[ -n "$android_sdk" && -f "$android_sdk/platforms/android-35/android.jar" ]] || \
    fail "Set ANDROID_HOME to an Android SDK with platform android-35 installed."
[[ -d "$android_sdk/build-tools/35.0.0" ]] || \
    fail "Install Android SDK build-tools 35.0.0 before running this script."
java_version="$(java -version 2>&1)"
[[ "$java_version" == *'version "17.'* ]] || fail "Use JDK 17 for the pinned Android Gradle plugin."
gradle_version="$(gradle --version)"
[[ "$gradle_version" == *'Gradle 8.9'* ]] || fail "Use Gradle 8.9 for Android Gradle plugin 8.7.3."
installed_targets="$(rustup target list --installed)"
for target in aarch64-linux-android x86_64-linux-android; do
    [[ $'\n'"$installed_targets"$'\n' == *$'\n'"$target"$'\n'* ]] || \
        fail "Missing Rust target $target; add it with rustup target add $target first."
done
# All output is staged under ignored generated/. Dependencies may be fetched by
# cargo/Gradle, but this script never installs SDKs, toolchains or system packages.
export ANDROID_HOME="$android_sdk"
export CARGO_TARGET_DIR="$repo_root/target"
export CARGO_INCREMENTAL=0
if [[ "$reuse_bindings" == true ]]; then
    [[ -f jacs-mobile/generated/kotlin/ai/hai/jacs/jacs_mobile.kt ]] || \
        fail "Generate current Kotlin bindings before using --reuse-bindings."
else
    bash jacs-mobile/scripts/generate-bindings.sh
fi
stage="$repo_root/jacs-mobile/generated/android-project"
mkdir -p "$stage/library/src/main/kotlin" "$stage/library/src/main/jniLibs"
cp -R jacs-mobile/distribution/android/. "$stage/"
cp -R jacs-mobile/generated/kotlin/. "$stage/library/src/main/kotlin/"
mkdir -p "$stage/library/src/main/kotlin/ai/hai/jacs/platform"
cp jacs-mobile/platforms/android/JacsKeystore.kt "$stage/library/src/main/kotlin/ai/hai/jacs/platform/"
# Align ELF load segments for Android devices using 16 KiB memory pages.
RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384" \
cargo ndk -t arm64-v8a -t x86_64 -p 30 \
    -o "$stage/library/src/main/jniLibs" build -p jacs-mobile --release --locked
gradle --no-daemon --project-dir "$stage" \
    :library:assembleRelease :library:publishReleasePublicationToBundleRepository
python3 jacs-mobile/scripts/check-android-package.py "$stage"
echo "AAR: $stage/library/build/outputs/aar/library-release.aar"
echo "Maven bundle with JNA dependency metadata: $stage/library/build/maven"
