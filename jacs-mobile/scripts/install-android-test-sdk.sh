#!/usr/bin/env bash
# Install only missing instrumentation dependencies. Existing license receipts
# must be provisioned independently; this script never accepts SDK terms.
set -euo pipefail
fail() { echo "jacs-mobile Android SDK: $*" >&2; exit 1; }
[[ $# == 1 ]] || fail "usage: $0 ANDROID_SDK_ROOT"
android_sdk="$(cd "$1" && pwd)"
sdkmanager="$android_sdk/cmdline-tools/latest/bin/sdkmanager"
[[ -x "$sdkmanager" && -s "$android_sdk/licenses/android-sdk-license" ]] || \
    fail "Existing SDK tools and independently provisioned licenses are required."
command -v timeout >/dev/null || fail "GNU timeout is required."

package_complete() {
    local root="$1" relative="$2"
    [[ -s "$root/$relative/package.xml" ]] || return 1
    case "$relative" in
        emulator)
            # Match the headless instrumentation launch. Plain -version loads
            # the GUI backend and can fail on unrelated Qt dependencies.
            [[ -x "$root/$relative/emulator" ]] && \
                timeout 15 "$root/$relative/emulator" -no-window -version ;;
        platform-tools)
            [[ -x "$root/$relative/adb" ]] && \
                timeout 15 "$root/$relative/adb" version ;;
        system-images/android-35/google_apis/x86_64)
            [[ -s "$root/$relative/system.img" && -s "$root/$relative/ramdisk.img" && \
                -s "$root/$relative/kernel-ranchu" ]] ;;
        *) return 1 ;;
    esac
}

staging=''
cleanup() { [[ -z "$staging" ]] || rm -rf -- "$staging"; }
trap cleanup EXIT
for package in emulator platform-tools 'system-images;android-35;google_apis;x86_64'; do
    relative="${package//;/\/}"
    if package_complete "$android_sdk" "$relative"; then
        echo "Using installed Android SDK package: $package"
        continue
    fi
    installed=false
    for attempt in 1 2 3; do
        staging="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/jacs-android-sdk.XXXXXX")"
        cp -R "$android_sdk/licenses" "$staging/licenses"
        echo "Installing $package (attempt $attempt of 3)"
        # Both the SDK download staging and Android cache belong to this
        # attempt. A corrupt ZIP cannot be reused by the next attempt, and no
        # shared SDK cache, installed package, or user settings are removed.
        # EOF still makes missing/unaccepted licenses fail.
        if ANDROID_USER_HOME="$staging/android-user" \
            timeout 600 "$sdkmanager" --sdk_root="$staging" --install "$package" </dev/null && \
            package_complete "$staging" "$relative"; then
            destination="$android_sdk/$relative"
            mkdir -p "$(dirname "$destination")"
            if [[ -e "$destination" ]]; then
                mv "$destination" "$staging/previous-package"
            fi
            if ! mv "$staging/$relative" "$destination"; then
                # A cross-filesystem mv may leave a partial copy. The prior
                # package is already in staging, so this destination contains
                # only files from this failed promotion.
                if ! rm -rf -- "$destination"; then
                    recovery="$staging"
                    staging='' # Preserve the prior package for recovery.
                    fail "Could not remove failed promotion; staging preserved at $recovery."
                fi
                if [[ -e "$staging/previous-package" ]]; then
                    if ! mv "$staging/previous-package" "$destination"; then
                        backup="$staging/previous-package"
                        staging='' # Preserve the prior package for recovery.
                        fail "Could not restore prior package; preserved at $backup."
                    fi
                fi
                fail "Could not install verified package $package."
            fi
            installed=true
        else
            echo "SDK package $package was not completely installed on attempt $attempt." >&2
        fi
        cleanup
        staging=''
        if [[ "$installed" == true ]]; then break; fi
    done
    [[ "$installed" == true ]] || fail "SDK package $package failed after 3 clean attempts."
done
