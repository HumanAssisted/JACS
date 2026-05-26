# `@jacs/wasm` Vite + Playwright smoke

Minimal Vite project + Playwright check that proves the
`@jacs/wasm` package shape works inside a real bundler (Task 020
acceptance criterion).

## Run locally

```bash
# From the JACS workspace root:
make build-wasm        # produces jacs-wasm/pkg + finalizes package.json

cd jacs-wasm/examples/vite-smoke
npm install
npx playwright install --with-deps chromium
npm run test           # vite build && vite preview && playwright test
```

A successful run prints `1 passed`. The Playwright check fails if
the page's `#output` element does not end with `SMOKE OK` within
15 s.

## How it wires `@jacs/wasm`

The `vite.config.ts` aliases the bare `@jacs/wasm` import to the
locally built `../../pkg/index.js`, and `@jacs/wasm/worker` to
`../../pkg/worker/index.js`. The package published on npm exposes
the same shape — the alias only exists so the smoke can run before
`npm publish` lands.

CI runs this check on every `wasm-v*` tag via
`release-wasm.yml` (Task 021), after `wasm-pack build` +
`finalize-pkg.sh`.
