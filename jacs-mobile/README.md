# jacs-mobile

JACS's mobile boundary depends on `jacs-core`, not the native `jacs` crate.
UniFFI records and a thread-safe handle expose creation, encrypted import/export,
identity updates, signing, verification, secret clearing and platform callbacks.
No private-key bytes are exposed through FFI. Encrypted material uses the same
base64 JSON fields and V2 envelope as `jacs-wasm`.

**New portable identities use `pq2025` (ML-DSA-87).**
`MobileAgent.createDefault()` generates an exportable post-quantum signing key
and propagates any error. There is no silent fallback to Ed25519 or ES256.
The explicit `create(algorithm)` constructor remains available for compatibility.

## Two custody modes

| Mode | Protection | Transfer |
| --- | --- | --- |
| Default: transferable ML-DSA-87 (`pq2025`) software key | Core encrypts the key; a random envelope password is protected by biometric Keychain/Keystore | Export encrypted material with a fresh generated transfer code |
| Explicit compatibility: Ed25519/ES256 software key | Same encrypted wrapping flow, selected explicitly when an existing integration requires it | Same encrypted material transfer |
| Explicit compatibility: native hardware ES256 signer | Secure Enclave or AndroidKeyStore signs through `PlatformSigner` | Export returns `NotExportable`; adding another device needs a new key plus delegation/rotation |

Hardware keys and transferable private keys cannot be the same key. Android
Keystore stores the wrapping key for the transferable mode; it does not export
an Android Keystore signing key. Android's default backing is device-dependent;
the adapter's `requireStrongBox` mode fails if StrongBox is unavailable.

Biometrics protect access to the portable ML-DSA key's wrapping secret. They do
not require changing its signing algorithm to ES256. The same `pq2025` identity
can be unlocked and transferred between Android, iOS and the browser. The
native ES256 callback adapters are retained for explicit compatibility and are
never selected automatically if post-quantum creation or unlocking fails.

Native creation quickstarts (run off the UI thread):

```kotlin
val agent = MobileAgent.createDefault() // always PQ2025
val store = JacsKeystore("jacs-agent-wrapping-key")
store.createWrappingKey()
// Authenticate store.prepareProtect() with BiometricPrompt, then call
// store.finishProtect(agent, authenticatedCipher) and persist the ciphertext.
```

```swift
let agent = try MobileAgent.createDefault() // always pq2025
let store = JacsKeychain(service: "ai.hai.jacs")
let material = try store.protect(agent: agent, account: "agent-id")
// Persist encrypted material; call agent.clearSecrets() when the session ends.
```

Imports retain and verify their declared algorithm. Applications that require
post-quantum identities must require `Pq2025` in their trusted registration and
`importPinned` expectations; a legacy identity is not silently converted.

## Build and generate Kotlin/Swift

From the repository root, with the repository Rust toolchain installed:

```sh
cargo test -p jacs-mobile --test portable -- --nocapture
bash jacs-mobile/scripts/generate-bindings.sh
```

The generator is pinned with the runtime to UniFFI 0.31.2. Host generation
produces `generated/swift/JacsMobile.swift`, its C header/modulemap, and Kotlin
under `generated/kotlin/ai/hai/jacs`. Include these files in the consuming app.
Generated files are build outputs, not hand-maintained source.

For Android, install the Android NDK and `cargo-ndk`, add the Rust Android
targets, then build the native libraries (API 30 minimum for these adapters):

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo ndk -t arm64-v8a -t x86_64 -p 30 -o jacs-mobile/generated/jniLibs build -p jacs-mobile --release
```

Add the generated Kotlin, `platforms/android/JacsKeystore.kt`, native `.so`
files and UniFFI's JNA Android runtime dependency to the app. The application
supplies `androidx.biometric` and the `USE_BIOMETRIC` permission. For the
transferable mode, call `prepareProtect`/`prepareUnlock`, authenticate their
Cipher using `BiometricPrompt.CryptoObject`, then pass the authenticated Cipher
to `finishProtect`/`finishUnlock` on a worker thread. Persist the returned
`WrappedMaterial` atomically in app-private storage. Never persist the password.
Exclude these device-bound records from Android backup or treat restoration
without their wrapping key as a recoverable missing-key condition.

On macOS, build `jacs-mobile` for `aarch64-apple-ios` and
`aarch64-apple-ios-sim`; package the static libraries and generated header in an
XCFramework with `xcodebuild -create-xcframework`. Add generated Swift and
`platforms/ios/JacsKeychain.swift`. The Keychain path uses
`WhenUnlockedThisDeviceOnly` and `biometryCurrentSet`; set the app's
`NSFaceIDUsageDescription`. Biometric enrollment changes intentionally invalidate
access. Keep a separate, explicitly protected recovery/transfer copy if recovery
is required. Simulator success does not validate Secure Enclave behavior.

`JacsSecureEnclaveSigner` calls `.ecdsaSignatureMessageX962SHA256`.
`JacsKeystoreSigner` calls `SHA256withECDSA`; complete biometric authentication
before calling Rust, within its 15-second authorization window. Both convert DER
ECDSA to P1363; Rust normalizes low-S and verifies every callback signature.
Construct a hardware agent with a new unsigned agent identity JSON containing
`jacsId`, `jacsVersion`, and metadata, then persist its signed exported document.
Reload it with the same OS key. Callback `clearSecrets` revokes the Rust handle's
access and releases session state; it does not delete a persistent OS key or
cancel Android's system-wide authentication window.

Loading an iOS hardware signer checks the private key class, P-256 type/size and
Secure Enclave token instead of trusting its tag. Loading an Android signer
checks `KeyInfo` for the configured biometric-strong-only authentication,
15-second duration and SHA-256 signing policy; unknown or weaker policies fail
closed. Android loading does not promise StrongBox backing. The per-use AES
wrapping key supports enrollment invalidation; Android does not guarantee that
property for the optional signing key's positive authentication window.

## React Native and web

The `PlatformSigner` callback uses the same UniFFI metadata as the other APIs.
Use a C++ TurboModule generated by `uniffi-bindgen-react-native` for Hermes;
ordinary Hermes does not execute the existing browser WASM package.

In a consuming React Native TurboModule library, pin matching generator/runtime
versions, copy `ubrn.config.example.yaml` to `ubrn.config.yaml`, and adjust the
checkout path. With `uniffi-bindgen-react-native@0.31.0-5` and matching
`@ubjs/core`, the upstream commands are:

```sh
yarn ubrn build android --and-generate
yarn ubrn build ios --and-generate
```

The generator creates TypeScript and C++/JSI plus native module installation.
The application still must wire the Swift/Kotlin biometric adapters to its
native module: do not put key custody callbacks in JavaScript or send plaintext
keys through a JS bridge. Initialize the generated module before calling it.
See the [upstream setup guide](https://jhugman.github.io/uniffi-bindgen-react-native/guides/rn/getting-started.html)
and [configuration reference](https://jhugman.github.io/uniffi-bindgen-react-native/reference/config-yaml.html).

For the binding files alone, without an app scaffold, run
`bash jacs-mobile/scripts/generate-rn-bindings.sh` from the repository root.
This pinned generation path has been exercised against this crate and produces
`generated/typescript/jacs_mobile.ts` and `generated/cpp`. Install
`@ubjs/core@0.31.0-5` in the consuming package. The generated `MobileAgentLike`
uses `ArrayBuffer` for byte fields and the `MobileAlgorithm` enum; application
adapters must map these types explicitly instead of treating the generated
module as the existing WASM class.

Browsers can use the existing `jacs-wasm` with exactly the same encrypted material.
UBRN's `web`/`wasm2` targets are alternative packaging routes; they require their
own runtime integration and verification. Sharing Rust sources and metadata does
not mean an Android native library can be loaded as browser WASM.

## Transfer and trust

1. Obtain an authenticated, short-lived receiver-bound relay session and the
   expected registered agent ID/public key independently of the transfer blob.
2. Unlock on the phone, call `generateTransferCode`, then `exportEncryptedAgent`.
   Display the code only on the phone; send only `materialToJson` ciphertext to
   the authenticated relay. Authenticate requests with `buildRequestAuthHeader`
   over their exact method, URL, transmitted body bytes and expected audience.
3. Receive the ciphertext once. Call `importPinned` to check the expected agent
   ID/key/algorithm, or `reencryptTransferredMaterial` to validate and immediately
   rewrap using the destination storage password without keeping a live handle.
4. Persist only newly encrypted material, and call `clearSecrets` on all live
   transfer handles. The destination password must differ from the transfer code.

This crate has no HTTP transport. Receiver authentication, session expiry,
atomic one-shot consumption and replay prevention belong to the relay. Import
validates the signed identity as well as the encrypted key; parsing material
alone is not verification. The six-word transfer code has 66 random bits using
the bundled 2048-word vocabulary and is not a wallet mnemonic.

For a registered identity edit, call `prepareAgentUpdateJson` to sign a candidate
while keeping the current version active. Authenticate the registration request
with that current handle and commit the exact candidate with
`commitAgentUpdateJson` only after the registry explicitly accepts it. A rejected
or interrupted request leaves the active identity unchanged. `updateAgent`
performs an immediate local update and is intended for workflows that do not
need this registry acceptance step.

Run KDF and biometric operations off the UI thread. Rust erases owned password
buffers and decrypted private-key state, but Kotlin/Swift/JavaScript strings and
FFI copies cannot be guaranteed erased. Do not log material passwords, transfer
codes, PRF outputs, callback messages or private state. Relock on app background,
logout and completion. Never fall back to server signing on biometric failure.

## Assemble native distribution packages

The assembly scripts use the checked-in templates under `distribution/` and
the real generated bindings. They do not download SDKs or install toolchains.
Cargo and Gradle may resolve their ordinary package dependencies. Both scripts
fail with a specific missing-prerequisite message before building.

**Android AAR:** install JDK 17, Gradle 8.9, `cargo-ndk`, Android SDK platform 35
and build-tools 35.0.0, an Android NDK, and Rust targets
`aarch64-linux-android`/`x86_64-linux-android`. Set `ANDROID_HOME` and
`ANDROID_NDK_HOME`, then run:

```sh
bash jacs-mobile/scripts/build-android-aar.sh
```

The Gradle/JDK/API versions follow the pinned
[Android Gradle plugin 8.7 compatibility requirements](https://developer.android.com/build/releases/agp-8-7-0-release-notes).

Output is `generated/android-project/library/build/outputs/aar/library-release.aar`,
containing generated Kotlin, `JacsKeystore`, `arm64-v8a`/`x86_64` Rust libraries,
the biometric manifest permission and consumer R8 rules. The script also
produces a **local** Maven repository at
`generated/android-project/library/build/maven`, with coordinate
`ai.hai:jacs-mobile:0.13.0` and the transitive JNA Android dependency. Consume
that Maven bundle to retain dependency metadata. When importing the bare AAR,
also declare `implementation("net.java.dev.jna:jna:5.18.1@aar")` in the app;
an AAR does not embed its Maven dependencies. The app provides its own
`androidx.biometric` UI and calls the CryptoObject flow described above.

**iOS XCFramework and Swift package:** run on macOS with full Xcode selected,
the iPhoneOS/iPhoneSimulator SDKs, and Rust targets `aarch64-apple-ios`,
`aarch64-apple-ios-sim` and `x86_64-apple-ios` installed:

```sh
bash jacs-mobile/scripts/build-ios-xcframework.sh
```

Output `generated/ios-package` is a local SwiftPM package containing the Rust
`JacsMobileFFI.xcframework` (arm64 device and arm64/x86_64 simulator slices), its
C header/modulemap, generated Swift and the native Keychain adapter. Add that
directory in Xcode, select the `JacsMobile` package product, and use
`import JacsMobile` for generated APIs and `import JacsMobilePlatform` for the
Keychain/Secure Enclave classes. Set the app's Face ID usage description.
The script refuses to overwrite an existing XCFramework; move an old output
aside before rebuilding. No artifact is uploaded or published externally.

These packaging scripts have syntax and prerequisite-failure checks only in
this environment. AAR/XCFramework assembly and native adapter compilation
require the SDK-equipped builders above and remain release validation steps.

## Verification scope

Rust integration tests cover all three algorithms, exact core/material JSON
interoperation, registered-key pinning, wrong passwords, rewrapping, relocking,
non-exportable callback signers, failed biometric callbacks, atomic identity
updates and strict JSON parsing. Generating Swift/Kotlin code is distinct from
compiling or running an app. Release acceptance additionally requires Android
and iOS device tests for biometric cancellation, enrollment invalidation,
background relocking, hardware signatures and phone-to-browser transfer.

An additional host smoke test executes generated UniFFI bindings against the
real dynamic library, with an independent Python `cryptography` P-256 callback.
On Linux after `generate-bindings.sh` (requires Python `cryptography`):

```sh
target/debug/jacs-mobile-bindgen generate --library target/debug/libjacs_mobile.so --language python --out-dir jacs-mobile/generated/python --no-format
ln -sfn ../../../target/debug/libjacs_mobile.so jacs-mobile/generated/python/libjacs_mobile.so
PYTHONPATH=jacs-mobile/generated/python python3 jacs-mobile/tests/ffi_smoke.py
```

This exercises actual cross-language calls, callback signatures, typed callback
failures and secret eviction, but makes no claim about device biometrics.
