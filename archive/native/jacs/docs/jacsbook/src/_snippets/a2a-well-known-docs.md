| Endpoint | Purpose |
|----------|---------|
| `/.well-known/agent-card.json` | A2A Agent Card with JWS signature |
| `/.well-known/jwks.json` | Stable ML-DSA-87 root JWK; ES256 only when explicitly selected |
| `/.well-known/jacs-compat-binding.json` | Only for explicit ES256 compatibility: native-root-signed binding to the claimed JACS identity |
| `/.well-known/jacs-agent.json` | JACS agent descriptor |
| `/.well-known/jacs-pubkey.json` | JACS public key |
| `/.well-known/jacs-extension.json` | JACS provenance extension descriptor |
