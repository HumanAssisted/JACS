# Android biometric vault

`JacsBiometricVault` is the ready-to-use Android library boundary for transferable
PQ2025 (ML-DSA-87) identities. It owns the unlocked Rust agent, prompts with the
platform `BiometricPrompt`, and stores an atomic encrypted record in the app's
`noBackupFilesDir`. Neither a raw private key nor the local wrapping password is
returned to the app. Android API 30 or later and enrolled **strong** biometrics
are required. There is no device-credential, user-password, or server fallback.

Create one vault per application-owned alias, on the main thread (normally in
`Activity.onCreate`). Call operations after the activity resumes. Do not share
one alias between concurrent vault instances or application processes: a
per-alias OS file lock rejects a second owner with `BUSY` until the first vault
closes and its worker drains. Crypto,
Argon2, and file operations run on a serial worker; prompts and callbacks run on
the main thread.

```kotlin
val vault = JacsBiometricVault(activity, "com.example.identity.primary")
val request = vault.create("Create your private identity", object : JacsVaultCallback<JacsVaultIdentity> {
    override fun onSuccess(identity: JacsVaultIdentity) {
        // Public signed identity and public key only; vault now owns the session.
    }
    override fun onError(error: JacsVaultException) {
        // Present an appropriate retry/enrollment/recovery UI for error.code.
    }
})
// Optional: request.cancel() is thread-safe and idempotent.
```

- `create(title, callback)` creates a PQ key, authenticates the exact AES
  `CryptoObject`, persists encrypted material, and opens an owned session.
  Existing records are never replaced.
- `unlock(title, callback)` reloads the record, validates the existing AES key's
  full authentication policy, prompts, then imports the encrypted PQ identity.
- `signMessageJson(...)` and `buildRequestAuthHeader(...)` use the owned session.
  No method exposes an unlocked `MobileAgent` that can escape lifecycle locking.
- `createTransfer(callback)` generates the six-word transfer code in Rust,
  exports encrypted material, and locks **before** returning code and ciphertext.
  Display the code locally; upload only ciphertext. No transport is included.
- `receive(materialJson, transferCode, expectedAgentId, expectedPublicKey, title,
  callback)` verifies the authenticated registration's identity/key pin, rejects
  non-PQ material, and stores it behind a fresh biometric-protected local secret.
- `lock()` is the logout/relock operation. It retains ciphertext for future
  unlocks. `delete(callback)` explicitly erases the encrypted record and wrapping
  key. `close()` is terminal and releases the activity registration and worker.

The owner activity stopping automatically locks and cancels pending operations;
destruction closes the vault. Recreate it for a new activity. Cancellation,
backgrounding, and logout invalidate pending generations: a late biometric
success or completed worker import is discarded and its secrets cleared. A
prompt mismatch or duplicate authorization cannot reuse a `CryptoObject`.
Cancellation cannot roll back a ciphertext file commit already in progress, but
it never publishes the resulting unlocked session. Cancellation of a completed
request has no effect on later sessions.

`JacsVaultException.Code` distinguishes `CANCELLED`, `BACKGROUNDED`, `CLOSED`,
`BUSY`, `LOCKED`, `UNAVAILABLE`, `NOT_ENROLLED`, `LOCKOUT`, `PERMANENT_LOCKOUT`,
`KEY_INVALIDATED`, `KEY_POLICY`, `MISSING_RECORD`, `ALREADY_EXISTS`,
`INVALID_RECORD`, `INTEGRITY`, `STORAGE`, and `CRYPTO`. Authentication failures
that the platform permits retrying are nonterminal; lockout and cancellation
finish the request. Enrollment changes or device lock changes may invalidate
the wrapping key. Recover from a separately authorized encrypted transfer;
never silently replace that key and pretend the old ciphertext was recovered.

The wrapping key is AES-256/GCM, non-exportable, with strong-biometric-only
per-use authentication and biometric-enrollment invalidation. Policy validation
uses Android's documented `KeyInfo` duration `-1` for per-use keys; creation
expresses this as timeout `0`. AAD is sent only after authorization. The wrapper
does not claim StrongBox or hardware-backed PQ signing: the portable PQ key is
unlocked in Rust memory. JVM/FFI strings cannot be reliably zeroed, so wrapping
password copies stay scoped to import/export; mutable password buffers are wiped.

## Verification

The existing `check-android-source.py` compiles all vault/adaptor source against
Android API classes and runs independent DER checks plus 255 state cases,
including 250 cancellation/completion races. The package script also compiles
an instrumentation APK from `tests/android-instrumented`, using test-only
AndroidX runner dependencies. On an already provisioned API 30+ emulator/device:

```sh
gradle --project-dir jacs-mobile/generated/android-project :library:connectedDebugAndroidTest
```

These device tests exercise real AndroidKeyStore rejection of weak aliases,
missing-key failure, real Rust PQ material and Android atomic-record persistence.
They do not forge biometric authorization or claim to verify a real sensor.
For sensor acceptance on a device with enrolled strong biometrics: create,
relock/unlock, cancel and background during each prompt, cancel during Argon2
work, change enrollment then unlock (expect invalidation), verify signing fails
after logout, and complete a pinned encrypted transfer into another runtime.
Keep any emulator enrollment automation separate from assertions about physical
sensor behavior. No HAI API or app integration is required or included.
