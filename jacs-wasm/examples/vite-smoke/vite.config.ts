import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveWasmPackage } from "./resolve-wasm-package.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wasmPackage = resolveWasmPackage({
  exampleDir: __dirname,
  env: process.env,
});

// Default to the locally built ../../pkg candidate. Post-publish verification
// explicitly sets JACS_WASM_PACKAGE_ROOT and JACS_WASM_EXPECTED_VERSION; the
// resolver then fails closed instead of falling back to the local candidate.
export default defineConfig({
  plugins: [wasm()],
  resolve: {
    alias: [
      {
        find: /^@hai\.ai\/jacs-wasm\/worker$/,
        replacement: wasmPackage.aliases["@hai.ai/jacs-wasm/worker"],
      },
      {
        find: /^@hai\.ai\/jacs-wasm$/,
        replacement: wasmPackage.aliases["@hai.ai/jacs-wasm"],
      },
    ],
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
