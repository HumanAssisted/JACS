// PRD §2 quickstart — lives here so the source tree `tsc --noEmit`
// fails fast if the published TypeScript surface drifts from PRD
// §4.3. Not executed; `expectAssignable`-style assertions are
// expressed as plain variable declarations whose annotations encode
// the contract.
//
// This file is intentionally trivial — every type assertion below
// reflects a load-bearing PRD signature. Removing an assertion is a
// PRD-level change; the assertions are the contract.

/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */

import {
  algorithmFromPublicKeyLength,
  createAgreementJson,
  createEphemeral,
  createVerifier,
  importEncryptedAgent,
  importEncryptedAgentFiles,
  initJacsWasm,
  localStore,
  type Algorithm,
  type CoreAgentHandle,
  type EncryptedAgentFiles,
  type JacsWasmError,
} from "../../index.js";

// PRD §2: `await initJacsWasm()` returns void.
const _init: Promise<void> = initJacsWasm();

// PRD §4.3: `createEphemeral` returns `Promise<CoreAgentHandle>`.
const _ephemeral: Promise<CoreAgentHandle> = createEphemeral("ed25519");

// PRD §4.3: `createVerifier(publicKeyBase64, algorithm)` returns
// `Promise<CoreAgentHandle>`.
const _verifier: Promise<CoreAgentHandle> = createVerifier(
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "ed25519",
);

// PRD §4.3: `importEncryptedAgent(materialJson, password)` returns
// `Promise<CoreAgentHandle>`.
const _imported: Promise<CoreAgentHandle> = importEncryptedAgent(
  "{}",
  "hunter2",
);

// PRD §4.3: `importEncryptedAgentFiles(files, password)` — object form,
// no positional algorithm.
const _filesShape: EncryptedAgentFiles = {
  configText: "{}",
  agentText: "{}",
  publicKeyBytes: new Uint8Array(32),
  encryptedPrivateKeyBytes: new Uint8Array(64),
};
const _importedFiles: Promise<CoreAgentHandle> = importEncryptedAgentFiles(
  _filesShape,
  "hunter2",
);

// algorithm helper exported for tests.
const _algo: Algorithm = algorithmFromPublicKeyLength(32);

// `localStore` shape matches PRD §4.3.
const _save: void = localStore.saveEncryptedAgent("k", "{}");
const _load: string | null = localStore.loadEncryptedAgent("k");
const _saveDoc: void = localStore.saveDocument("k", "{}");
const _loadDoc: string | null = localStore.loadDocument("k");
const _keys: string[] = localStore.listKeys("prefix-");
const _keysAll: string[] = localStore.listKeys();
const _remove: void = localStore.remove("k");
const _clear: void = localStore.clearAll();

// Agreement helper (free function).
const _agreement: string = createAgreementJson(
  "{}",
  '["agent-1"]',
  "Do you agree?",
  null,
);

// `CoreAgentHandle` exposes the PRD §4.3 instance methods.
type _ExpectMethods = {
  signMessageJson: (data: string) => string;
  verifyJson: (signed: string) => string;
  verifyWithKeyJson: (
    signed: string,
    publicKeyBase64: string,
    algorithm: string,
  ) => string;
  exportAgent: () => string;
  getPublicKeyBase64: () => string;
  algorithm: () => string;
  isUnlocked: () => boolean;
  clearSecrets: () => void;
  signAgreementJson: (agreementJson: string, role: string) => string;
  verifyAgreementJson: (agreementJson: string, signersJson: string) => string;
  metrics: () => string;
};
// Structural check: every method on `_ExpectMethods` must exist on
// `CoreAgentHandle` with a compatible signature.
const _instanceMethodCheck: (h: CoreAgentHandle) => _ExpectMethods = (h) => ({
  signMessageJson: h.signMessageJson.bind(h),
  verifyJson: h.verifyJson.bind(h),
  verifyWithKeyJson: h.verifyWithKeyJson.bind(h),
  exportAgent: h.exportAgent.bind(h),
  getPublicKeyBase64: h.getPublicKeyBase64.bind(h),
  algorithm: h.algorithm.bind(h),
  isUnlocked: h.isUnlocked.bind(h),
  clearSecrets: h.clearSecrets.bind(h),
  signAgreementJson: h.signAgreementJson.bind(h),
  verifyAgreementJson: h.verifyAgreementJson.bind(h),
  metrics: h.metrics.bind(h),
});

// Stable error wire shape.
const _err: JacsWasmError = {
  code: "InvalidPassword",
  message: "bad password",
};
