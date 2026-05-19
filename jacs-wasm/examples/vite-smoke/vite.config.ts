import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Rewrite the bare `@jacs/wasm` import to the locally built `../../pkg/`
// directory so the smoke can run before the package is published. CI
// builds `jacs-wasm/pkg/` first via `wasm-pack build` + `finalize-pkg.sh`
// and then runs `npm install && npm run build && npx playwright test`
// inside this directory.
export default defineConfig({
  plugins: [wasm()],
  resolve: {
    alias: {
      "@jacs/wasm": path.resolve(__dirname, "../../pkg/index.js"),
      "@jacs/wasm/worker": path.resolve(__dirname, "../../pkg/worker/index.js"),
    },
  },
  build: {
    target: "esnext",
  },
  server: {
    port: 4173,
    strictPort: true,
  },
  preview: {
    port: 4173,
    strictPort: true,
  },
});
