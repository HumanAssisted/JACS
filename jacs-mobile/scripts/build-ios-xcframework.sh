#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
fail() { echo "jacs-mobile iOS build: $*" >&2; exit 1; }
reuse_bindings=false
if [[ "${1:-}" == --reuse-bindings && $# == 1 ]]; then
    reuse_bindings=true
elif [[ $# != 0 ]]; then
    fail "Usage: $0 [--reuse-bindings] (reuse only bindings generated from this checkout)."
fi
[[ "$(uname -s)" == Darwin ]] || fail "Run on macOS with full Xcode installed."
for program in cargo rustup xcodebuild xcrun; do
    command -v "$program" >/dev/null || fail "Missing $program. Install the documented prerequisites first."
done
xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1 || fail "Select a full Xcode installation with an iPhoneOS SDK."
xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1 || fail "Xcode iPhoneSimulator SDK is unavailable."
installed_targets="$(rustup target list --installed)"
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    [[ $'\n'"$installed_targets"$'\n' == *$'\n'"$target"$'\n'* ]] || \
        fail "Missing Rust target $target; add it with rustup target add $target first."
done
stage="$repo_root/jacs-mobile/generated/ios-package"
[[ ! -e "$stage/JacsMobileFFI.xcframework" ]] || \
    fail "Output already exists at $stage/JacsMobileFFI.xcframework. Move it aside before rebuilding."
export CARGO_TARGET_DIR="$repo_root/target"
export CARGO_INCREMENTAL=0
export IPHONEOS_DEPLOYMENT_TARGET=13.0
if [[ "$reuse_bindings" == true ]]; then
    for filename in JacsMobile.swift JacsMobileFFI.h JacsMobileFFI.modulemap; do
        [[ -f "jacs-mobile/generated/swift/$filename" ]] || \
            fail "Generate current Swift bindings before using --reuse-bindings."
    done
else
    bash jacs-mobile/scripts/generate-bindings.sh
fi
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    cargo build -p jacs-mobile --release --locked --target "$target"
done
mkdir -p "$stage/Sources/JacsMobile" "$stage/Sources/JacsMobilePlatform" \
    "$stage/Tests/JacsMobilePlatformTests" \
    "$stage/build/headers" "$stage/build/device" "$stage/build/simulator"
cp jacs-mobile/distribution/ios/Package.swift "$stage/Package.swift"
cp jacs-mobile/generated/swift/JacsMobile.swift "$stage/Sources/JacsMobile/"
cp jacs-mobile/platforms/ios/*.swift "$stage/Sources/JacsMobilePlatform/"
cp jacs-mobile/tests/ios/*.swift "$stage/Tests/JacsMobilePlatformTests/"
cp jacs-mobile/generated/swift/JacsMobileFFI.h "$stage/build/headers/"
cp jacs-mobile/generated/swift/JacsMobileFFI.modulemap "$stage/build/headers/module.modulemap"
cp target/aarch64-apple-ios/release/libjacs_mobile.a "$stage/build/device/libJacsMobileFFI.a"
xcrun lipo -create \
    target/aarch64-apple-ios-sim/release/libjacs_mobile.a \
    target/x86_64-apple-ios/release/libjacs_mobile.a \
    -output "$stage/build/simulator/libJacsMobileFFI.a"
xcodebuild -create-xcframework \
    -library "$stage/build/device/libJacsMobileFFI.a" -headers "$stage/build/headers" \
    -library "$stage/build/simulator/libJacsMobileFFI.a" -headers "$stage/build/headers" \
    -output "$stage/JacsMobileFFI.xcframework"
xcrun swift package --package-path "$stage" dump-package >/dev/null
echo "Swift package: $stage"
echo "Add this directory as a local Swift Package in Xcode. Import JacsMobile and JacsMobilePlatform."
echo "Assembly does not validate Swift source compilation or device biometrics; build your consuming app and run device tests."
