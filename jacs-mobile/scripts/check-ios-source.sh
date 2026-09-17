#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
fail() { echo "jacs-mobile Swift source check: $*" >&2; exit 1; }
[[ "$(uname -s)" == Darwin ]] || fail "Run on macOS with an installed Xcode iPhoneSimulator SDK."
command -v xcrun >/dev/null || fail "xcrun is unavailable; select an existing full Xcode installation."
[[ -f jacs-mobile/generated/swift/JacsMobile.swift ]] || \
    fail "Generate bindings with bash jacs-mobile/scripts/generate-bindings.sh first."
sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
architecture="$(uname -m)"
case "$architecture" in
    arm64|x86_64) ;;
    *) fail "Unsupported simulator host architecture: $architecture" ;;
esac
stage="$repo_root/jacs-mobile/generated/ios-typecheck/$architecture"
mkdir -p "$stage/headers"
cp jacs-mobile/generated/swift/JacsMobileFFI.h "$stage/headers/"
cp jacs-mobile/generated/swift/JacsMobileFFI.modulemap "$stage/headers/module.modulemap"
# Compile the generated module first so the separate platform adapter imports
# its actual exported types. No Rust archive link or device execution occurs.
xcrun --sdk iphonesimulator swiftc -swift-version 5 -parse-as-library \
    -emit-module -module-name JacsMobile -sdk "$sdk" \
    -target "$architecture-apple-ios13.0-simulator" -I "$stage/headers" \
    jacs-mobile/generated/swift/JacsMobile.swift \
    -emit-module-path "$stage/JacsMobile.swiftmodule"
xcrun --sdk iphonesimulator swiftc -swift-version 5 -parse-as-library \
    -emit-module -module-name JacsMobilePlatform -sdk "$sdk" \
    -target "$architecture-apple-ios13.0-simulator" -I "$stage" -I "$stage/headers" \
    jacs-mobile/platforms/ios/*.swift \
    -emit-module-path "$stage/JacsMobilePlatform.swiftmodule"
echo "PASS: generated Swift, biometric vault/session, and Keychain/Secure Enclave adapters compile against the iOS simulator SDK."
echo "This source check does not link an XCFramework or exercise device biometrics."
