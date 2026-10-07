# Browser and mobile

## Browser

```sh
npm install --save-exact @hai.ai/jacs-wasm@0.15.0
```

Use the [browser guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-wasm/README.md)
for WASM initialization, workers, signing/verification and encrypted storage.
The npm scope is `@hai.ai`; older `@jacs/wasm` examples predate this release.
The browser package shares the portable core and does not load the native
Node module or expose native email/filesystem integrations.

## Android and iOS

`jacs-mobile` provides UniFFI bindings and platform host libraries. See the
[mobile guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-mobile/README.md),
[Android lifecycle and custody guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-mobile/platforms/android/README.md)
and [iOS guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-mobile/platforms/ios/README.md).

The hardware-backed platform store protects access to software PQ key
material; it does not perform native hardware ML-DSA signing. Publishing the
Rust crate is separate from assembling host bundles and accepting behavior
on physical devices.
