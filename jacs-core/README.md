# jacs-core

Portable JACS protocol layer. Compiles for native and `wasm32-unknown-unknown`.
Performs no I/O — no filesystem, no network, no environment variables.

See [`docs/jacs/JACS_WASM_PRD.md`](../docs/jacs/JACS_WASM_PRD.md) for the full
split rationale.

## Encrypted private-key envelopes

`jacs-core::envelope` reads two on-disk formats and writes one:

- **V2 JSON envelope (Argon2id) — current writer + reader.** Encodes
  `{ "jacsEncryptedPrivateKeyVersion": 2, "cipher": "AES-256-GCM", "kdf": { "name": "Argon2id", "version": 19, "m_cost_kib": …, "t_cost": …, "p_cost": … }, "salt": "<base64url>", "nonce": "<base64url>", "ciphertext": "<base64url>" }`.
  Always starts with `{`.
- **Legacy raw-binary PBKDF2 envelope — read-only.** `salt(16) || nonce(12) || ciphertext`,
  PBKDF2-HMAC-SHA256 at 600k iterations with a 100k fallback for pre-0.6.0
  keys. No new writes ever produce this format.

### Reserved magic prefixes

Inputs whose first 4 bytes match the ASCII pattern `^J[A-Z]{2}[0-9]$`
(for example `JAA1`, `JAC2`, `JAS9`) are **reserved for future envelope
formats** — memory-hard KDF variants, post-quantum AEAD wrappers, and the
like. `decrypt_private_key` rejects them up front with
`CoreError::UnsupportedAlgorithm("<prefix>")` so they aren't misclassified
as malformed legacy PBKDF2 noise.

V2 envelopes are unaffected (they begin with `{`) and the probability that
a 16-byte random PBKDF2 salt accidentally collides with the reserved
pattern is roughly 1 in 170,000 — small enough that mis-rejecting one in
practice is vanishingly unlikely.

## See also

- [`jacs`](../jacs/README.md) — native facade. Filesystem, DNS, HTTP, MCP, CLI, storage.
- [`jacs-wasm`](../jacs-wasm) — browser wrapper around `jacs-core` (Task 015+).
