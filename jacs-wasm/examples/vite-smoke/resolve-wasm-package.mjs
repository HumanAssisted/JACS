import {
  lstatSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import path from "node:path";

const PACKAGE_NAME = "@jacs/wasm";
const PACKAGE_ROOT_ENV = "JACS_WASM_PACKAGE_ROOT";
const EXPECTED_VERSION_ENV = "JACS_WASM_EXPECTED_VERSION";

function fail(message) {
  throw new Error(`[vite-smoke] ${message}`);
}

function envValue(env, name) {
  const value = env[name];
  return typeof value === "string" ? value.trim() : "";
}

function endsWithInstalledPackageRoot(candidate) {
  const parts = path.normalize(candidate).split(path.sep).filter(Boolean);
  return (
    parts.length >= 3 &&
    parts.at(-3) === "node_modules" &&
    parts.at(-2) === "@jacs" &&
    parts.at(-1) === "wasm"
  );
}

function assertRegularFileWithin(packageRoot, relativePath) {
  const candidate = path.resolve(packageRoot, relativePath);
  const relative = path.relative(packageRoot, candidate);
  if (
    relative === "" ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    fail(`${relativePath} escapes the installed package root`);
  }

  let metadata;
  try {
    metadata = statSync(candidate);
  } catch {
    fail(`installed package is missing ${relativePath}`);
  }
  if (!metadata.isFile()) {
    fail(`installed package path ${relativePath} is not a regular file`);
  }

  const realCandidate = realpathSync(candidate);
  const realRelative = path.relative(packageRoot, realCandidate);
  if (
    realRelative === "" ||
    realRelative === ".." ||
    realRelative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(realRelative)
  ) {
    fail(`${relativePath} resolves outside the installed package root`);
  }
  return realCandidate;
}

function parseManifest(packageRoot) {
  const manifestPath = assertRegularFileWithin(packageRoot, "package.json");
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    fail(
      `cannot parse installed package.json: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    fail("installed package.json must contain a JSON object");
  }
  return manifest;
}

/**
 * Resolve the Vite aliases for either the local pre-publish build or an exact
 * registry-installed package. Supplying JACS_WASM_PACKAGE_ROOT explicitly
 * selects registry mode; there is no fallback from registry mode to ../../pkg.
 */
export function resolveWasmPackage({ exampleDir, env = process.env }) {
  if (!path.isAbsolute(exampleDir)) {
    fail("exampleDir must be an absolute path");
  }

  const configuredRoot = envValue(env, PACKAGE_ROOT_ENV);
  const expectedVersion = envValue(env, EXPECTED_VERSION_ENV);
  const localRoot = path.resolve(exampleDir, "../../pkg");

  if (!configuredRoot) {
    if (expectedVersion) {
      fail(`${EXPECTED_VERSION_ENV} requires ${PACKAGE_ROOT_ENV}`);
    }
    return {
      mode: "local",
      packageRoot: localRoot,
      aliases: {
        [PACKAGE_NAME]: path.join(localRoot, "index.js"),
        [`${PACKAGE_NAME}/worker`]: path.join(localRoot, "worker/index.js"),
      },
    };
  }

  if (!expectedVersion) {
    fail(`${PACKAGE_ROOT_ENV} requires ${EXPECTED_VERSION_ENV}`);
  }
  if (!path.isAbsolute(configuredRoot)) {
    fail(`${PACKAGE_ROOT_ENV} must be an absolute path`);
  }

  const requestedRoot = path.normalize(configuredRoot);
  if (!endsWithInstalledPackageRoot(requestedRoot)) {
    fail(`${PACKAGE_ROOT_ENV} must end in node_modules/@jacs/wasm`);
  }

  let rootMetadata;
  try {
    rootMetadata = lstatSync(requestedRoot);
  } catch {
    fail(`${PACKAGE_ROOT_ENV} does not exist: ${requestedRoot}`);
  }
  if (rootMetadata.isSymbolicLink()) {
    fail(`${PACKAGE_ROOT_ENV} must not be a symlink`);
  }
  if (!rootMetadata.isDirectory()) {
    fail(`${PACKAGE_ROOT_ENV} is not a directory`);
  }

  const packageRoot = realpathSync(requestedRoot);
  if (!endsWithInstalledPackageRoot(packageRoot)) {
    fail(`${PACKAGE_ROOT_ENV} resolves outside node_modules/@jacs/wasm`);
  }
  if (packageRoot === localRoot) {
    fail(`${PACKAGE_ROOT_ENV} must not resolve to the local ../../pkg build`);
  }

  const manifest = parseManifest(packageRoot);
  if (manifest.name !== PACKAGE_NAME) {
    fail(`expected package name ${PACKAGE_NAME}, found ${String(manifest.name)}`);
  }
  if (manifest.version !== expectedVersion) {
    fail(
      `expected version ${expectedVersion}, found ${String(manifest.version)}`,
    );
  }
  if (manifest.exports?.["."]?.import !== "./index.js") {
    fail("package exports['.'].import must equal ./index.js");
  }
  if (manifest.exports?.["./worker"]?.import !== "./worker/index.js") {
    fail("package exports['./worker'].import must equal ./worker/index.js");
  }

  const mainEntry = assertRegularFileWithin(packageRoot, "index.js");
  const workerEntry = assertRegularFileWithin(packageRoot, "worker/index.js");
  assertRegularFileWithin(packageRoot, "worker/jacs-worker.js");

  return {
    mode: "registry",
    packageRoot,
    aliases: {
      [PACKAGE_NAME]: mainEntry,
      [`${PACKAGE_NAME}/worker`]: workerEntry,
    },
  };
}
