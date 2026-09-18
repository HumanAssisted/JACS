#!/usr/bin/env bash
# Uses the runner's existing Android SDK licenses. Never runs --licenses or
# answers yes to an SDK agreement. The fixed API image is a test dependency.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
fail() { echo "jacs-mobile Android instrumentation: $*" >&2; exit 1; }
android_sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
[[ -n "$android_sdk" && -s "$android_sdk/licenses/android-sdk-license" ]] || \
    fail "An independently provisioned Android SDK license is required; this script does not accept terms."
for program in java gradle timeout; do command -v "$program" >/dev/null || fail "Missing $program"; done
sdkmanager="$android_sdk/cmdline-tools/latest/bin/sdkmanager"
avdmanager="$android_sdk/cmdline-tools/latest/bin/avdmanager"
[[ -x "$sdkmanager" && -x "$avdmanager" ]] || fail "Existing SDK command-line tools (latest/bin) are required."
[[ -f jacs-mobile/generated/android-project/library/build/outputs/apk/androidTest/debug/library-debug-androidTest.apk ]] || \
    fail "Run build-android-aar.sh first to compile the native library and instrumentation APK."
image_package='system-images;android-35;google_apis;x86_64'
# EOF makes missing/unaccepted licenses fail, rather than silently accepting them.
"$sdkmanager" --sdk_root="$android_sdk" --install emulator platform-tools "$image_package" </dev/null
[[ -x "$android_sdk/emulator/emulator" && -x "$android_sdk/platform-tools/adb" ]] || fail "SDK emulator/adb installation is incomplete."
[[ -f "$android_sdk/system-images/android-35/google_apis/x86_64/package.xml" ]] || fail "API 35 x86_64 image is unavailable (check existing license provisioning)."
[[ -c /dev/kvm ]] || fail "A Linux runner with /dev/kvm is required for the bounded emulator gate."
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    [[ "${GITHUB_ACTIONS:-}" == true ]] || fail "Current user requires read/write access to /dev/kvm."
    # The hosted runner is ephemeral; this only grants emulator access to KVM.
    sudo chmod a+rw /dev/kvm
fi
export ANDROID_AVD_HOME="${RUNNER_TEMP:-$repo_root/jacs-mobile/generated}/jacs-test-avd"
mkdir -p "$ANDROID_AVD_HOME"
# 'no' answers the optional custom hardware-profile question, not SDK terms.
printf 'no\n' | "$avdmanager" create avd --force --name jacs-api35 --package "$image_package" --device pixel_2
adb="$android_sdk/platform-tools/adb"
export ANDROID_SERIAL=emulator-5580
emulator_log="$repo_root/jacs-mobile/generated/android-emulator.log"
"$android_sdk/emulator/emulator" -avd jacs-api35 -port 5580 -no-window -no-audio \
    -no-boot-anim -no-snapshot -wipe-data -gpu swiftshader_indirect \
    -camera-back none -camera-front none >"$emulator_log" 2>&1 &
emulator_pid=$!
cleanup() {
    timeout 10 "$adb" -s "$ANDROID_SERIAL" emu kill >/dev/null 2>&1 || true
    kill "$emulator_pid" 2>/dev/null || true
}
trap cleanup EXIT
"$adb" start-server >/dev/null
boot_deadline=$((SECONDS + 300))
while [[ "$(timeout 10 "$adb" -s "$ANDROID_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)" != 1 ]]; do
    if ! kill -0 "$emulator_pid" 2>/dev/null || (( SECONDS >= boot_deadline )); then
        tail -80 "$emulator_log"
        fail "Emulator failed to boot within 300 seconds."
    fi
    sleep 3
done
"$adb" -s "$ANDROID_SERIAL" shell input keyevent 82
"$adb" -s "$ANDROID_SERIAL" shell settings put global window_animation_scale 0
"$adb" -s "$ANDROID_SERIAL" shell settings put global transition_animation_scale 0
"$adb" -s "$ANDROID_SERIAL" shell settings put global animator_duration_scale 0
timeout 900 gradle --no-daemon --project-dir jacs-mobile/generated/android-project \
    :library:connectedDebugAndroidTest
