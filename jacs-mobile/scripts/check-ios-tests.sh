#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fail() { echo "jacs-mobile iOS tests: $*" >&2; exit 1; }
[[ "$(uname -s)" == Darwin ]] || fail "Run on macOS with the Xcode iPhoneSimulator SDK."
stage="$repo_root/jacs-mobile/generated/ios-package"
[[ -d "$stage/JacsMobileFFI.xcframework" ]] || fail "Assemble the current XCFramework first."
[[ -f "$stage/Tests/JacsMobilePlatformTests/JacsBiometricVaultTests.swift" ]] || fail "Reassemble the package with the current XCTest sources."
simulator_id="${JACS_IOS_TEST_SIMULATOR_ID:-}"
if [[ -z "$simulator_id" ]]; then
    simulator_id="$(xcrun simctl list devices available --json | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
matches = [d["udid"] for runtime, rows in devices.items() if ".iOS-" in runtime
           for d in rows if d.get("isAvailable") and d["name"].startswith("iPhone")]
if not matches:
    sys.exit("No available iPhone simulator. Install a runtime through Xcode first.")
print(matches[0])
')"
fi
cd "$stage"
xcodebuild -scheme JacsMobile -destination "platform=iOS Simulator,id=$simulator_id" \
    -configuration Release -parallel-testing-enabled NO \
    -derivedDataPath "$stage/test-build" ENABLE_TESTABILITY=YES test
echo "PASS: Swift lifecycle/cancellation XCTest and noninteractive simulator Keychain policy tests."
echo "Physical-device biometric acceptance remains a separate interactive check."
