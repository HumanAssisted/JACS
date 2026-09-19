# Native compatibility fixtures

These public verification and envelope test vectors preserve interoperability with
the archived native implementation without making active tests depend on archive
paths. `wasm_compat/` comes from `archive/native/jacs/tests/fixtures/wasm_compat/`;
the agreement and method contracts come from `archive/native/binding-core/tests/fixtures/`.

The retained vectors originate in the public JACS tree at commit
`992953ea77d4c9a16953aee28e4a1e5d26e62200`. Public keys, signatures, and the historical
Argon2id/PBKDF2 envelopes are known synthetic interoperability test data, never
production identities. Envelope tests use the documented test password and compare
the decrypted key's public identity with the fixed public-key vector. Preserve
these encrypted envelopes byte-for-byte to retain cross-version reader coverage.

Raw private-key fixtures are deliberately excluded. Private signing and import
tests generate fresh keys at runtime and do not recover the fixed vector's key
for signing. The archive follows the same policy for raw private-key test files.

These fixtures retain the repository's Apache-2.0 license.

`human_complete_document.json` is a synthetic public fixture for first-version
human identity and complete document signing. It contains only signed public
identity/document bytes, public key and expected content/checksum. Both artifacts
were checked with archived `NonSigningVerifier::verify_with_key` and
`Agent::verify_hash`; no private key or recovery secret is included. The standalone
`tests/portable-interop/native_document_check.rs` harness verifies this fixture,
fresh output and tamper rejection without adding archived dependencies to the
active portable workspace.
