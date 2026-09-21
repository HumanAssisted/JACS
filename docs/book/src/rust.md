# Rust libraries

Use `jacs-core = "=0.15.0"` for the no-I/O portable protocol and crypto layer.
Use `jacs = "=0.15.0"` for native filesystem, email, media, trust and integration
APIs; enable `a2a`, `agreements` or `attestation` as needed. Both packages are
published and supported, with separate dependency graphs.

Start with the [native Rust API](native/rust/library.html),
[document operations](native/rust/documents.html),
[agreements](native/rust/agreements.html),
[email signing](native/guides/email-signing.html) or
[storage backends](native/advanced/storage.html).
The [portable core guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-core/README.md)
describes the smaller embedding surface.

The installed portable CLI is `jacs`; extended command examples use `jacs-compat`.
See [packages](packages.md) for the complete inventory and release evidence.
