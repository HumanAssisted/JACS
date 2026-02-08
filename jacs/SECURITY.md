# Security Policy

## Security model

- **Passwords**: The private key password must be set only via the `JACS_PRIVATE_KEY_PASSWORD` environment variable. It is never stored in config files.
- **Keys**: Private keys are encrypted at rest (AES-256-GCM with PBKDF2). Public keys and config may be stored on disk.
- **Paths**: Paths built from untrusted input (e.g. `publicKeyHash` from documents) are validated to prevent traversal (`require_relative_path_safe`); key and data directory path builders enforce this. Validation rejects empty segments, `.`, `..`, null bytes, and Windows drive-prefixed paths (`C:\...`, `D:/...`).
- **Schema filesystem access**: Filesystem schema loading is opt-in (`JACS_ALLOW_FILESYSTEM_SCHEMAS=true`) and restricted to configured allowed roots using normalized/canonical path containment checks.
- **Network transport policy**: HAI registration verification enforces HTTPS for `HAI_API_URL` (localhost HTTP allowed for local testing only).
- **No secrets in config**: Config files and env overrides must not contain passwords or other secrets.
- **A2A foreign verification**: Foreign wrapped-artifact signatures are only marked verified when signer keys are resolved and verified cryptographically; unresolved foreign keys return explicit `Unverified` status.

## Reporting vulnerabilities

If you think you have identified a security issue with a JACS, do not open a public issue.
To responsibly report a security issue, please navigate to the "Security" tab for the repo, and click "Report a vulnerability".

Be sure to include as much detail as necessary in your report. As with reporting normal issues, a minimal reproducible example will help the maintainers address the issue faster.

Thank you for supporting JACS.
