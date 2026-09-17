| Policy | Behavior |
|--------|----------|
| `open` | Accept all agents without verification |
| `verified` | Require a valid Agent Card JWS against the same-origin JWKS and a durable `jacsId:jacsVersion` key pin (**default**). This is origin/key continuity, not proof of the claimed native JACS identity. |
| `strict` | Require an explicitly trusted native JACS root. ES256 cards must also carry the fixed-path compatibility binding, whose native signature, identity/version, binding hash, compatibility JWK/kid, scope, expiry, and signed issuance time all verify. Bindings are accepted for at most seven days after `issuedAt` (with five minutes of future clock skew), and the verifier durably pins the latest observed hash, kid, and `issuedAt`; a newer root-signed binding advances the pin and older replays fail closed. |

> **Lifecycle boundary:** The absolute seven-day freshness check also applies
> on first contact, independently of `expiresAt`. Local discovery generation
> refreshes an authentic binding after six days under the shared issuance lock,
> preserving its scopes and explicit expiry. Once a newer native-root-signed
> binding is observed, JACS also rejects rollback to the old hash/kid. Use an
> earlier `expiresAt` when old compatibility keys must stop working sooner, and
> distribute the refreshed binding promptly after rotation or compromise.
