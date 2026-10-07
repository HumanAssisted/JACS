# Python library

```sh
python -m venv .venv
.venv/bin/python -m pip install jacs==0.15.0
```

Use the native Python library directly in services, tools and framework
adapters. Prebuilt wheels are available for the platforms in the release
inventory; custom source builds use maturin and Rust.

Start with the [simple API](native/python/simple-api.html),
[instance API](native/python/basic-usage.html),
[framework adapters](native/python/adapters.html) or
[API reference](native/python/api.html).

The [current package README](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacspy/README.md)
covers public approval verification, request/event authentication and the
optional CLI shim. Current extended CLI examples use `jacs-compat`; the shim's
downloaded `jacs` executable is the portable CLI.
