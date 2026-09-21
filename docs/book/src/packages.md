# Language and platform packages

Use MCP for a process boundary, or a direct package when embedding JACS.

| Integration | Package |
|---|---|
| Rust portable core | `jacs-core` |
| Portable CLI and MCP | `jacs-cli` (`jacs` executable), `jacs-mcp` library |
| Browser | `@hai.ai/jacs-wasm` |
| Native Node | `@hai.ai/jacs` |
| Python | `jacs` |
| Go | `github.com/HumanAssisted/JACS/jacsgo` |
| Native Rust compatibility | `jacs`, `jacs-binding-core`, `jacs-mcp-compat`, `jacs-cli-compat` |
| Mobile | `jacs-mobile` with the Android/iOS host libraries |

The five-crate portable workspace has no dependency on the native workspace.
Native bindings retain email, media and application integration APIs. Browser
WASM and mobile hosts share the portable crypto core; they do not expose every
native filesystem, transport or storage integration.

Check the [verified release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
for exact published versions, platform coverage and provenance. Mobile bundle
delivery and physical-device acceptance are separate from publishing the Rust crate.

See the [browser guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-wasm/README.md),
[mobile guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-mobile/README.md)
and [native language reference](native/index.html).
