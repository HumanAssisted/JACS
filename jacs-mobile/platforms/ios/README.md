# iOS biometric vault

`JacsBiometricVault` is the default custody API for transferable **pq2025**
identities. It creates and signs with portable Rust. Face ID / Touch ID protects
a random wrapping password; it does not change the signing algorithm to ES256.

```swift
import JacsMobile
import JacsMobilePlatform

let vault = JacsBiometricVault(service: "com.example.identity")
let operation = vault.create(account: "primary", reason: "Create your signing identity") { result in
    switch result {
    case .success(let session):
        // Retain the session for the intended foreground use.
        session.signMessageJSON("{\"hello\":\"world\"}") { signed in
            // Consume signed data. Do not log secrets or transfer codes.
            session.close()
        }
    case .failure(let error):
        // Handle the typed error; cancellation never selects a weaker key.
        handleVaultError(error)
    }
}
// operation.cancel() cancels a pending prompt/result. It is safe on the UI thread.
```

Call `unlock(account:reason:completion:)` for an existing identity. Receive an
encrypted transfer with `receive(material:code:expectedAgentID:expectedPublicKey:account:reason:completion:)`;
obtain the expected identity/key from an independently trusted source. This pins
and imports in Rust only after biometric authorization, then rewraps for the
device. To save an already imported transferable PQ identity, use
`protect(agent:account:reason:completion:)`.
**Protect consumes and clears the supplied Rust handle on all paths**; retain
the returned session, not the supplied handle. Encryption, key generation,
Keychain access and signing run on a worker queue; callbacks default to the
main queue. A single vault allows only one biometric prompt at a time.

Set `NSFaceIDUsageDescription` in the application's Info.plist. The authorization
policy is `deviceOwnerAuthenticationWithBiometrics`, with no passcode fallback
and no credential reuse from an earlier context. Lockout, missing enrollment,
cancellation and failed authentication are typed failures. The low-level
`JacsKeychain` password-only helper is retained for existing integrations;
its manual persistence and lifecycle are not the vault API.

## Persistence and recovery

A dedicated `service + ".biometric-vault.v1"` Keychain namespace holds one atomic
record: the Rust-encrypted material, its random 256-bit wrapping password and
the evaluated biometric domain. The signing private key is never put into
Swift as raw bytes. The record uses `biometryCurrentSet`,
`WhenPasscodeSetThisDeviceOnly`, no synchronization, and the data-protection
Keychain. Reads check account/service, accessibility, synchronization and the
presence/type of access control; they also require a fresh biometric policy and
matching biometric domain. Apple does not expose a public persisted-ACL flags
getter, so the vault never imports records from the legacy namespace or claims
to inspect private ACL internals.

`SecItemAdd` never replaces an existing account. Save failure clears the newly
created key and leaves an existing recovery record untouched. Cancellation can
race after the atomic save: in that case a **complete, locked record** remains.
Unlock the same account to recover it; retrying creation returns `alreadyExists`.
No partially persisted wrapping secret/material pair is possible.

Enrollment changes, passcode removal, device loss or lost Keychain records can
make the identity unrecoverable on that device. Keep an explicitly protected
recovery/transfer export if recovery is required. Do not silently create a new
identity under an existing account after an unlock failure.

## Session lifetime

The vault automatically invalidates pending prompts and all its sessions on
application background and protected-data loss. Call `vault.invalidate()` on
logout too. Pending and queued late callbacks cannot reopen a session. Call
`vault.resume()` after returning to an authorized foreground state, then unlock
again with a fresh biometric context. Resume itself does not unlock anything.

`session.close()` immediately rejects new work and queued results. A Rust call
already running may finish internally; its result is suppressed and the key is
cleared on the worker when that call ends. Sessions do not expose a raw
`MobileAgent` that could survive invalidation. Swift strings and FFI copies of
passwords cannot be guaranteed wiped; keep sessions short and never log them.

`session.createTransfer(completion:)` generates a fresh six-word code in Rust,
returns the code and encrypted material, and clears the session before delivery.
Display the code directly to the receiver; send only ciphertext to the relay.
The lower-level `exportEncryptedMaterial(password:completion:)` remains available
for explicit rewrapping. The Keychain wrapping password is never returned.
The receiver still pins the agent ID/key/algorithm
independently when importing. Transport and relay integration are separate.

## Tests

On macOS with Xcode and an installed iPhone simulator:

```sh
bash jacs-mobile/scripts/generate-bindings.sh
bash jacs-mobile/scripts/check-ios-source.sh
bash jacs-mobile/scripts/build-ios-xcframework.sh --reuse-bindings
bash jacs-mobile/scripts/check-ios-tests.sh
```

The XCTest sources use fake biometric callbacks for deterministic
cancellation/state tests and real noninteractive simulator Keychain queries
to reject weak or missing records. The script generates a minimal simulator
app host linked to the assembled Swift package, then verifies the app signature
and each built executable slice's embedded simulator Keychain entitlements
before running all tests. A hostless
SwiftPM test process lacks the application identity required by Keychain.
No developer account or production signing credentials are needed. These tests
do not claim that a simulator proves Face ID, Secure Enclave, or physical-device
enrollment behavior.

Before a device release, run an interactive test host linked to the generated
Swift package on a physical iPhone with its Face ID usage description:

1. Create a disposable PQ identity, authorize biometrics, sign, close, unlock and
   verify that the same public identity remains. Verify cancellation and lockout
   return failures without a passcode fallback or new identity.
2. Cancel during the prompt and after authorization while work is pending;
   background and log out at the same points. Confirm exactly one failure
   callback, inactive sessions, and failure of subsequent signing.
3. Kill/relaunch after saving and verify same-account recovery. Attempt creation
   twice and confirm the first identity is preserved. Interrupt after biometric
   success to cover the documented complete-record cancellation outcome.
4. Change enrolled biometrics and confirm the prior record cannot unlock. Test
   passcode removal on a disposable device. Restore using an independently
   protected recovery export, never a silent replacement identity.
5. Export using a generated transfer code, import/pin in the browser, sign there,
   and verify the same public key. Relock both sessions after completion.

Record device/OS, biometric type and results for this matrix. Physical-device
steps require user interaction and are not marked passed by the simulator job.
