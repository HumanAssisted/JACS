# Historical test vectors

The public keys, signed documents and encrypted key envelopes in `keys/` and
`wasm_compat/` preserve interoperability with the public JACS repository at
commit `992953e`. These disposable test identities and their documented test
passwords were already public; they must never represent a real agent or
protect user data.

The archive keeps the original public verification and encrypted-envelope
bytes. Plaintext private-key fixture files have been removed. Signing tests
generate fresh keys in memory, and decryption tests compare the derived public
key with the historical public-key oracle. Regeneration helpers write public
vectors and encrypted test envelopes only, never plaintext private-key files.

The WASM compatibility envelopes use the test password documented in
`../wasm_compat_fixtures.rs`. Other historical envelope passwords are explicit
test parameters in their consumers. Those values are public fixture data.

Command-line examples are documented in the archived native README and in
[jacs-examples](https://github.com/HumanAssisted/jacs-examples).
