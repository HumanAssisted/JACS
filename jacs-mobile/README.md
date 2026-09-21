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

## Custody modes

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

Use `JacsBiometricVault` for new native integrations. The Android vault owns the
activity prompt, encrypted atomic record, worker and unlocked session; the iOS
vault owns the biometric Keychain record and returns an invalidatable session.
Both create only PQ2025 identities, require biometric authorization, and reject
late results after cancellation, backgrounding or logout. Neither exposes its
local wrapping password or an unlocked handle that can outlive its session.

Follow the [Android vault guide](platforms/android/README.md) or
[iOS vault guide](platforms/ios/README.md) for creation, unlock, signing, encrypted
transfer, recovery and lifecycle calls. Android construction and prompt calls
belong on the main thread; the vault performs crypto and persistence on its
worker. The Swift vault also performs crypto and Keychain work on a worker queue.

The lower-level `MobileAgent`, `JacsKeystore` and `JacsKeychain` APIs remain for
explicit compatibility integrations. Such integrations must own their prompts,
persistence and lifecycle clearing. Their availability does not make an ordinary
software handle biometric-protected. Low-level imports retain and verify their
declared algorithm; the default vaults reject non-PQ material. Pin PQ2025 in the
trusted registration when the deployment requires post-quantum identities.

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
cargo ndk -t arm64-v8a -t x86_64 --platform 30 -o jacs-mobile/generated/jniLibs build -p jacs-mobile --release
```

Prefer the package assembly scripts below: they include all platform sources,
generated bindings, native libraries, permissions and dependency metadata.
For a manual Android integration, include all files under `platforms/android/`,
the generated Kotlin and native `.so` files, JNA's Android runtime, and the
`USE_BIOMETRIC` permission. The default vault uses Android's platform
`BiometricPrompt` on API 30+; it does not require an AndroidX biometric UI.
Its encrypted records live in `noBackupFilesDir`. Restoring a device-bound
record without its wrapping key cannot recover the identity.

For iOS, use the generated local Swift package or include all Swift platform
sources and the generated binding/native library. Set
`NSFaceIDUsageDescription`. The default vault uses `biometryCurrentSet` and
`WhenPasscodeSetThisDeviceOnly` for one atomic device-local record. Enrollment
changes or passcode removal can invalidate access. Keep a separate, explicitly
protected recovery/transfer copy if recovery is required. Simulator success
does not validate physical-device biometric or Secure Enclave behavior.

### Explicit ES256 hardware compatibility

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
The application still must connect the Swift/Kotlin biometric vault/session
APIs to its native module. Generating the Rust `MobileAgent` bindings alone does
not expose these native vault wrappers or protect a software handle. Keep key
custody callbacks native and never send plaintext keys through a JS bridge. Initialize the generated module before calling it.
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

The vaults provide local `createTransfer` and pinned `receive` operations.
`createTransfer` clears the source session before delivering the code and
ciphertext. It does not create a relay session, sign a HAI upload, or send HTTP.
Application integration must construct and authenticate the complete transfer
protocol inside its native session boundary; an exported blob alone is not a
HAI `signed_transfer`. The public HAI client contracts describe that protocol.

For a low-level integration that explicitly owns its unlocked handle:

1. Obtain an authenticated, short-lived receiver-bound relay session and the
   expected registered agent ID/public key independently of the transfer blob.
2. Unlock on the phone, call `generateTransferCode`, then `exportEncryptedAgent`.
   Display the code only on the phone. Bind `materialToJson` ciphertext to the
   intended session in the relay protocol, then authenticate its exact method,
   URL, transmitted body bytes and audience with `buildRequestAuthHeader`. Send
   the signed ciphertext bundle and authorization, never the code.
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

Run low-level KDF work off the UI thread and follow the platform prompt API
threading rules. The default vaults handle that scheduling. Rust erases owned password
buffers and decrypted private-key state, but Kotlin/Swift/JavaScript strings and
FFI copies cannot be guaranteed erased. Do not log material passwords, transfer
codes, PRF outputs, callback messages or private state. Relock on app background,
logout and completion. Never fall back to server signing on biometric failure.

## Assemble native distribution packages

The assembly scripts use the checked-in templates under `distribution/` and
the real generated bindings. They do not download SDKs or install toolchains.
Cargo and Gradle may resolve their ordinary package dependencies. Both scripts
fail with a specific missing-prerequisite message before building.

**Android AAR:** install JDK 17, Gradle 8.9, `cargo-ndk` 4.1.2, Android SDK platform 35
and build-tools 35.0.0, Android NDK 27.3.13750724, and Rust targets
`aarch64-linux-android`/`x86_64-linux-android`. Set `ANDROID_HOME` and
`ANDROID_NDK_HOME`, then run:

```sh
bash jacs-mobile/scripts/build-android-aar.sh
```

The Gradle/JDK/API versions follow the pinned
[Android Gradle plugin 8.7 compatibility requirements](https://developer.android.com/build/releases/agp-8-7-0-release-notes).

Output is `generated/android-project/library/build/outputs/aar/library-release.aar`,
containing generated Kotlin, the biometric vault/state/Keystore sources,
`arm64-v8a`/`x86_64` Rust libraries,
the biometric manifest permission and consumer R8 rules. The script also
produces a **local** Maven repository at
`generated/android-project/library/build/maven`, with coordinate
`ai.hai:jacs-mobile:<version>` (matching `jacs-mobile/Cargo.toml`) and the transitive
JNA Android dependency. Consume that Maven bundle to retain dependency metadata.
When importing the bare AAR,
also declare `implementation("net.java.dev.jna:jna:5.18.1@aar")` in the app;
an AAR does not embed its Maven dependencies. The vault provides the platform
biometric prompt; the app supplies operation titles, error/recovery UI and
foreground lifecycle integration as described in the Android guide.

**iOS XCFramework and Swift package:** run on macOS with full Xcode selected,
the iPhoneOS/iPhoneSimulator SDKs, and Rust targets `aarch64-apple-ios`,
`aarch64-apple-ios-sim` and `x86_64-apple-ios` installed:

```sh
bash jacs-mobile/scripts/build-ios-xcframework.sh
```

Output `generated/ios-package` is a local SwiftPM package containing the Rust
`JacsMobileFFI.xcframework` (arm64 device and arm64/x86_64 simulator slices), its
C header/modulemap, generated Swift, biometric vault/session classes and native
Keychain/Secure Enclave adapters. Add that
directory in Xcode, select the `JacsMobile` package product, and use
`import JacsMobile` for generated APIs and `import JacsMobilePlatform` for the
Keychain/Secure Enclave classes. Set the app's Face ID usage description.
The script refuses to overwrite an existing XCFramework; move an old output
aside before rebuilding. No artifact is uploaded or published externally.

The Android adapter and generated Kotlin compile with Kotlin 2.0.21 against
the Android 15/API 35 SDK and the actual JNA Android AAR. The independent host
test verifies 32 DER-to-P1363 conversions with Java's signature verifier and
rejects five malformed DER inputs. Reproduce this source check after generation:

```sh
python3 jacs-mobile/scripts/check-android-source.py
```

The command downloads checksum-pinned open-source Maven artifacts (about
240 MB); it neither installs Android SDK tools nor accepts SDK license terms.
It uses published AOSP API classes by default. Supply
`--api-jar "$ANDROID_HOME/platforms/android-35/android.jar"` to check against an
independently installed SDK's public API jar instead. Output is
`generated/android-typecheck.jar`; this is a compiled source test, not an AAR.

On an Xcode-equipped macOS machine, run
`bash jacs-mobile/scripts/check-ios-source.sh` after generation to compile both
Swift modules against the simulator SDK. Source compilation is a separate
gate from package assembly, simulator tests and physical-device acceptance.

The `mobile-bindings.yml` workflow also assembles both native distribution
packages on pull requests and uploads build artifacts for review. It reuses
the bindings generated and compiled earlier in each job. Android uses the
runner's existing SDK/NDK and JDK, checksum-pinned Gradle 8.9, and version-pinned
`cargo-ndk` 4.1.2. Assembly uses provisioned SDKs. The separate instrumentation
script may download a fixed emulator image using already provisioned licenses;
it never accepts SDK terms. The macOS job builds arm64 device and both simulator Rust archives
before assembling the XCFramework. Neither job publishes packages to a registry.
Package and simulator/emulator gates must pass on the current commit; source
compilation alone does not establish packaging or device runtime behavior.
Actual HAI API deployment and consuming mobile app integration are explicitly
deferred; these libraries do not enable production linking by themselves.

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

### Human signing and generated recovery

`MobileAgent.createHuman()` generates an ML-DSA-87 human identity in its first
self-signed version. Apps should use the owned `JacsBiometricVault.createHuman`
entry point on iOS/Android, retaining biometric custody and lifecycle guards.
No `MobileAgent` signing handle crosses an application bridge.

For durable recovery, use iOS `session.createRecovery` or Android
`vault.createRecovery`. The result contains a generated 128-bit code and encrypted
`AgentMaterial`; owned sessions lock before delivery and reject late results.
`vault.receiveRecovery` pins the expected ID/public key from authenticated
registration, normalizes pasted code formatting, rewraps behind local biometric
protection and refuses to replace any existing record. Wrong input leaves a
working record unchanged. Local restore alone never authorizes an application action.

The underlying UniFFI `exportRecovery()` returns `MobileRecoveryExport { code,
material }`; `importRecovery` takes the material, code and ID/key/algorithm pins.
These APIs expose no plaintext private key or OS wrapping secret. Display/input
copies of a recovery code are host-managed strings: never log or persist them,
and discard them on background. The six-word transfer APIs remain separate.

`verifyRecovery` on each owned vault performs a noninteractive read-back check and
returns only the verified signed identity JSON. It neither persists the material
nor installs an unlocked session. Compare its `jacsVersion` with the current
registered version before treating a backup as current. UniFFI's
`normalizeRecoveryCode` provides cheap syntax validation before prompts; malformed
paste is rejected before `receiveRecovery` requests biometrics. Native errors
separate invalid recovery code, identity mismatch, malformed material and locked
state; they never expose foreign exception details. A well-formed wrong code still
fails authenticated decryption; it cannot reliably be distinguished from modified
ciphertext with an invalid authentication tag.

On iOS, `createRecovery` returns `JacsBiometricRecovery` with redacted descriptions
and reflection. `delete(account:completion:)` deliberately removes only that local
record and closes its sessions. Cancellation before the mutation keeps the record.
For an invalidated record, first verify the candidate recovery and current version,
then explicitly delete and restore. `receiveRecovery` never auto-overwrites a record.

For a complete independently verifiable document, use iOS
`session.signDocumentJSON` or Android `vault.signDocumentJson` (UniFFI:
`MobileAgent.signDocumentJson`). Exact input JSON becomes `content`; JACS generates
fresh root IDs/dates before signing and computes the standard `jacsSha256` afterward.
Existing `signMessageJson` retains its original minimal-message semantics.

For an already prepared complete unsigned document, use
`session.signPreparedDocumentJSON` or Android `vault.signPreparedDocumentJson`
(UniFFI: `MobileAgent.signPreparedDocumentJson`). Pass serialized core
`PreparedDocumentV2`, including its frozen envelope, signature input and request
context. The owned key validates the complete preparation before signing; the
returned envelope changes only its signature value and derived checksum. The
host still checks that this is the person's exact reviewed action. Existing
authenticated-session, cancellation and background fences apply. These methods
neither regenerate headers nor expose a private key. Prepared JSON has a separate
3 MiB transport limit because it includes both the envelope and base64 signing
input; the existing 1 MiB limit on other JSON entry points remains unchanged.

### Staged key rotation

Owned vaults expose `prepareKeyRotation`, `keyRotationStatus`,
`signRotationDocumentJSON` (Android `signRotationDocumentJson`),
`createRotationRecovery`, `commitKeyRotation` and `discardKeyRotation`.
Each uses fresh existing biometric protection. iOS takes `account`, `reason` and
`completion`; Android takes `title` and `callback`. Candidate signing/recovery
and discard also require the exact `candidateVersion`. Preparation/status returns
`MobilePublicIdentity` with validated public identity, key, hash and PEM. No candidate handle or local password
crosses the application bridge; sign/recovery operations clear temporary signers
before returning.

Preparation atomically stores at most one encrypted candidate beside the old
material. Repeated preparation returns that candidate. The old identity retains
its ID/original version and authorizes the V2 rotation proof. This differs from a
management-credential replacement that creates a new lineage. Existing biometric
ACL/Keystore policies and the JACS envelope remain unchanged. Legacy vault records
remain readable; Android uses its v2 record container only while a stage exists.

Persist the candidate before server submission. Sign the candidate enrollment
challenge through `signRotationDocumentJSON` and the old-key management challenge
through the existing old-key session. If the old key has a committed recovery copy,
export the candidate recovery generation, read it back with `verifyRecovery` pinned
to the candidate, and obtain save acknowledgment before server activation. HAI owns
these generation and acknowledgment transactions; JACS never marks a code saved.

After server acceptance, reconcile authenticated status and pass that exact signed
identity JSON and public key to `commitKeyRotation`. Promotion atomically replaces
the active material and removes the pending copy. A failed local write leaves both
old and pending ciphertext available; reopen and reconcile. Exact commit replay
is safe. Cancellation/background suppresses late results but does not discard a
persisted candidate. Call `discardKeyRotation` only after authoritative
nonacceptance; never discard merely because a response was lost. Removing a local
vault deliberately removes both copies and remains separate from server revocation.
An unreadable or unverifiable pending stage blocks rotation without replacing the
working active key. This does not trigger automatic deletion of either copy.

UniFFI supplies `prepareKeyRotation(password)`, `validateKeyRotation(material,
password)`, `signRotationDocumentJson(material,password,json)`,
`exportRotationRecovery(material,password)` and
`commitKeyRotation(material,password,acceptedIdentityJson,acceptedPublicKey)`.
These low-level native methods are implementation details of the owned vault and
must not be bridged as unlocked handles or wrapping passwords.

`vault.inspect` is nonprompting and reports absent, present/locked or unreadable.
It does not claim biometric usability or invalidation. Android validates the public
identity already present in its encrypted-material record; iOS returns no identity
from a locked Keychain value. After unlock, iOS `session.describe` and Android
`vault.describe` return `MobilePublicIdentity` containing validated `agentJson`,
`publicKeyBase64`, `publicKeyHash`, `publicKeyPem` and `algorithm`. No secondary
public metadata store is created. Obtain authoritative pins from registration
before restore or activation, regardless of local inspect metadata.
iOS reports a known decode failure as unreadable and returns other unexpected
Keychain statuses as typed errors; an entitlement or storage failure is not a
claim that the stored identity needs restoring.
