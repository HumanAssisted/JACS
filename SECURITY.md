# Security Policy

## Current hardening highlights

- Untrusted filesystem path inputs are validated centrally (`require_relative_path_safe`) and include checks for traversal segments, null bytes, and Windows drive-prefixed absolute paths.
- Filesystem schema loading is opt-in and restricted to configured allowed roots via normalized/canonical path containment checks.
- HAI registration verification endpoints require HTTPS (`HAI_API_URL`), with HTTP allowed only for localhost testing.
- A2A wrapped-artifact verification fails closed for unresolved foreign signer keys and reports explicit `Unverified` status until keys are resolved via configured key sources.

If you think you have identified a security issue with a JACS, do not open a public issue.
To responsibly report a security issue, please navigate to the "Security" tab for the repo, and click "Report a vulnerability".

Be sure to include as much detail as necessary in your report. As with reporting normal issues, a minimal reproducible example will help the maintainers address the issue faster.

Thank you for supporting JACS.
