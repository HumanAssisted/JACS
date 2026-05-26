# @jacs/wasm Worker smoke

Minimal browser fixture that proves `@jacs/wasm/worker` works
end-to-end (Task 019 acceptance criterion).

## Run

```bash
# From the JACS workspace root:
make build-wasm                                  # produces jacs-wasm/pkg
cd jacs-wasm/examples/worker-smoke
npm install
npm run dev                                      # serves index.html
```

Open the page; the `#output` element should end with `SMOKE OK`.

The page wires `@jacs/wasm/worker` via a relative bundler import
(`vite.config.ts` rewrites `@jacs/wasm` to the locally built
`../../pkg/`). The packaged version on npm is identical — the bundler
rewrite is only here so the smoke can run before the package is
published.
