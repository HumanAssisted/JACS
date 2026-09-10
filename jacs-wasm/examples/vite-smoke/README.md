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

With no extra environment variables, `vite.config.ts` aliases the bare
`@jacs/wasm` import to the locally built `../../pkg/index.js`, and
`@jacs/wasm/worker` to `../../pkg/worker/index.js`.

To test an exact package installed from npm, install it into this example and
select it explicitly:

```bash
npm install --no-save --ignore-scripts @jacs/wasm@0.13.0
JACS_WASM_PACKAGE_ROOT="$PWD/node_modules/@jacs/wasm" \
  JACS_WASM_EXPECTED_VERSION=0.13.0 \
  npm test
```

Registry mode validates the package name, exact version, export map, main
entry, worker entry, and worker bootstrap before Vite starts. The package root
must be an absolute, non-symlinked `node_modules/@jacs/wasm` directory. A bad
or missing registry package fails immediately and never falls back to the
local `../../pkg` candidate.

CI runs this check on every `wasm-v*` tag via
`release-wasm.yml` (Task 021), after `wasm-pack build` +
`finalize-pkg.sh`.
