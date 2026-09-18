# HTML Inline Signed Email Fixtures

These RFC 5322 fixtures support the HTML-inline signed email migration.
They are intentionally static and do not require HAI API state. Early tests
only require parseability; verifier-specific tests add semantic expectations
as the transport implementation lands.

| File | Case |
|---|---|
| `01_plain_text.eml` | Current plain text source body before HTML generation |
| `02_text_with_attachment.eml` | Plain text source body plus one user attachment |
| `03_generated_html.eml` | Generated HTML with hidden envelope, footer, and inline logo |
| `04_reply_with_quoted_markers.eml` | Reply where quoted content repeats reserved markers |
| `05_missing_logo.eml` | Inline envelope and footer with no logo artifact |
| `06_stripped_logo.eml` | HTML still references the logo CID after the MIME image part was stripped |
| `07_mismatched_logo.eml` | Hidden envelope and logo marker intentionally disagree |
| `08_tampered_body.eml` | Text body changed after the envelope marker was generated |
