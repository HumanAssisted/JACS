/**
 * Dependency-free JACS document-v2 signature-input construction.
 *
 * This module is deliberately separate from the native napi entrypoint.  It
 * runs in Hermes, browsers, and other ES2020 runtimes without Node `crypto`,
 * `Buffer`, `fs`, WebAssembly, or a global `TextEncoder`.
 *
 * It does not sign and does not accept a server-supplied digest as truth.  An
 * approval client passes the complete frozen envelope to
 * `buildDocumentSignatureInputV2`, hashes the returned bytes with its platform
 * SHA-256 implementation, and compares the result with the prepared record.
 */

export const DOCUMENT_V2_SIGNATURE_PROFILE = 'jacs-document-v2';
export const DOCUMENT_V2_PLACEMENT_KEY = 'jacsSignature';
export const HAI_SIGNATURE_INPUT_DIGEST_DOMAIN = 'JACS-HAI-SIGNATURE-INPUT-V1';
export const HUMAN_APPROVAL_DOCUMENT_SIGNATURE_INPUT_DIGEST_DOMAIN =
  'JACS-HUMAN-APPROVAL-DOCUMENT-SIGNATURE-INPUT-V1';

const SIGNATURE_CONTENT_DOMAIN_V2 = 'jacs.signature.v2';
const SIGNATURE_CONTENT_VERSION_V2 = 'jacs-signature-v2';
const IGNORED_DOCUMENT_FIELDS = new Set([
  'jacsSha256',
  'jacsSignature',
  'jacsAgentSignature',
  'jacsAgreement',
  'jacsRegistration',
  'jacsTaskStartAgreement',
  'jacsTaskEndAgreement',
]);
const SIGNATURE_METADATA_FIELDS = new Set([
  'agentID',
  'agentVersion',
  'date',
  'iat',
  'jti',
  'signature',
  'signingAlgorithm',
  'publicKeyHash',
  'fields',
  'signatureContentVersion',
]);

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireWellFormedString(value, path) {
  if (typeof value !== 'string') throw new TypeError(`${path} must be a string`);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`${path} contains an unpaired high surrogate`);
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError(`${path} contains an unpaired low surrogate`);
    }
  }
  return value;
}

function canonicalize(value, path, ancestors) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError(`${path} contains a non-finite number`);
      if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
        throw new TypeError(`${path} contains an integer outside the I-JSON safe range`);
      }
      return JSON.stringify(value);
    case 'string':
      requireWellFormedString(value, path);
      return JSON.stringify(value);
    case 'object':
      break;
    default:
      throw new TypeError(`${path} contains a non-JSON ${typeof value} value`);
  }

  if (ancestors.has(value)) throw new TypeError(`${path} contains a cycle`);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const entries = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.prototype.hasOwnProperty.call(value, index)) {
          throw new TypeError(`${path}[${index}] is a sparse-array hole`);
        }
        entries.push(canonicalize(value[index], `${path}[${index}]`, ancestors));
      }
      return `[${entries.join(',')}]`;
    }
    if (!isRecord(value)) throw new TypeError(`${path} must be a plain JSON object`);

    const symbolKeys = Object.getOwnPropertySymbols(value).filter(
      (key) => Object.prototype.propertyIsEnumerable.call(value, key),
    );
    if (symbolKeys.length !== 0) throw new TypeError(`${path} contains a symbol key`);
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => {
      requireWellFormedString(key, `${path} key`);
      return `${JSON.stringify(key)}:${canonicalize(value[key], `${path}.${key}`, ancestors)}`;
    }).join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

/** RFC 8785/JCS canonical JSON used by the JACS v2 signature family. */
export function canonicalizeJson(value) {
  return canonicalize(value, '$', new Set());
}

/** UTF-8 encoder with no TextEncoder dependency (and no surrogate repair). */
export function encodeUtf8(value) {
  requireWellFormedString(value, 'UTF-8 input');
  const bytes = [];
  for (let index = 0; index < value.length; index += 1) {
    let codePoint = value.charCodeAt(index);
    if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
      const low = value.charCodeAt(index + 1);
      codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00);
      index += 1;
    }
    if (codePoint <= 0x7f) {
      bytes.push(codePoint);
    } else if (codePoint <= 0x7ff) {
      bytes.push(0xc0 | (codePoint >>> 6), 0x80 | (codePoint & 0x3f));
    } else if (codePoint <= 0xffff) {
      bytes.push(
        0xe0 | (codePoint >>> 12),
        0x80 | ((codePoint >>> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      );
    } else {
      bytes.push(
        0xf0 | (codePoint >>> 18),
        0x80 | ((codePoint >>> 12) & 0x3f),
        0x80 | ((codePoint >>> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      );
    }
  }
  return Uint8Array.from(bytes);
}

function requireNonEmptyString(value, path) {
  requireWellFormedString(value, path);
  if (value.length === 0) throw new TypeError(`${path} must be nonempty`);
  return value;
}

function validateMetadata(metadata) {
  if (!isRecord(metadata)) throw new TypeError('$.jacsSignature must be a plain object');
  const keys = Object.keys(metadata);
  if (keys.length !== SIGNATURE_METADATA_FIELDS.size
      || keys.some((key) => !SIGNATURE_METADATA_FIELDS.has(key))) {
    throw new TypeError('$.jacsSignature must contain exactly the document-v2 metadata fields');
  }
  requireNonEmptyString(metadata.agentID, '$.jacsSignature.agentID');
  requireNonEmptyString(metadata.agentVersion, '$.jacsSignature.agentVersion');
  requireNonEmptyString(metadata.date, '$.jacsSignature.date');
  if (!Number.isSafeInteger(metadata.iat)) {
    throw new TypeError('$.jacsSignature.iat must be a safe integer');
  }
  requireNonEmptyString(metadata.jti, '$.jacsSignature.jti');
  if (metadata.signature !== '') {
    throw new TypeError('$.jacsSignature.signature must be empty in a prepared envelope');
  }
  if (metadata.signingAlgorithm !== 'ed25519' && metadata.signingAlgorithm !== 'pq2025') {
    throw new TypeError('$.jacsSignature.signingAlgorithm must be ed25519 or pq2025');
  }
  requireNonEmptyString(metadata.publicKeyHash, '$.jacsSignature.publicKeyHash');
  if (metadata.signatureContentVersion !== SIGNATURE_CONTENT_VERSION_V2) {
    throw new TypeError('$.jacsSignature.signatureContentVersion must be jacs-signature-v2');
  }
  if (!Array.isArray(metadata.fields)) {
    throw new TypeError('$.jacsSignature.fields must be an array');
  }
}

function validateSignedMetadata(metadata) {
  if (!isRecord(metadata)) throw new TypeError('$.jacsSignature must be a plain object');
  if (typeof metadata.signature !== 'string' || metadata.signature.length === 0) {
    throw new TypeError('$.jacsSignature.signature must be nonempty in a signed document');
  }
  if (metadata.signatureContentVersion !== SIGNATURE_CONTENT_VERSION_V2) {
    throw new TypeError('$.jacsSignature.signatureContentVersion must be jacs-signature-v2');
  }
  if (!Array.isArray(metadata.fields)) {
    throw new TypeError('$.jacsSignature.fields must be an array');
  }
}

function buildSignatureInput(envelope, metadata) {
  const expectedFields = Object.keys(envelope)
    .filter((key) => key !== DOCUMENT_V2_PLACEMENT_KEY && !IGNORED_DOCUMENT_FIELDS.has(key))
    .sort();
  const actualFields = metadata.fields.map((field, index) =>
    requireNonEmptyString(field, `$.jacsSignature.fields[${index}]`));
  if (actualFields.length !== expectedFields.length
      || actualFields.some((field, index) => field !== expectedFields[index])) {
    throw new TypeError(
      '$.jacsSignature.fields must equal the complete sorted non-reserved document field set',
    );
  }

  // Native JACS signs every metadata member except `signature`, including
  // extension metadata unknown to this portable reader. Preserve it exactly.
  const signatureMetadata = Object.create(null);
  for (const key of Object.keys(metadata)) {
    if (key !== 'signature') signatureMetadata[key] = metadata[key];
  }
  const fields = actualFields.map((name) => ({ name, value: envelope[name] }));
  const preimage = canonicalizeJson({
    domain: SIGNATURE_CONTENT_DOMAIN_V2,
    placementKey: DOCUMENT_V2_PLACEMENT_KEY,
    fields,
    signatureMetadata,
  });
  return encodeUtf8(preimage);
}

/**
 * Reconstruct the exact bytes signed by the JACS document-v2 family.
 *
 * The envelope, not a hash supplied beside it, is authoritative.  This
 * function requires the signature's `fields` array to equal the complete
 * sorted set of non-reserved top-level fields and strips only
 * `jacsSignature.signature`, matching `jacs-core`.
 */
export function buildDocumentSignatureInputV2(envelope) {
  if (!isRecord(envelope)) throw new TypeError('JACS envelope must be a plain object');
  const metadata = envelope[DOCUMENT_V2_PLACEMENT_KEY];
  validateMetadata(metadata);
  return buildSignatureInput(envelope, metadata);
}

/**
 * Reconstruct a completed document's exact v2 signature input.
 *
 * Unlike the prepared-envelope helper, this accepts a nonempty signature and
 * preserves all other metadata members exactly, matching the native verifier.
 */
export function buildSignedDocumentSignatureInputV2(document) {
  if (!isRecord(document)) throw new TypeError('JACS document must be a plain object');
  const metadata = document[DOCUMENT_V2_PLACEMENT_KEY];
  validateSignedMetadata(metadata);
  return buildSignatureInput(document, metadata);
}

/**
 * Bytes a platform SHA-256 must hash for TP-31's
 * `candidateSignatureInputDigest`.
 */
export function buildHaiSignatureInputDigestPreimageV1(envelope) {
  const label = encodeUtf8(HAI_SIGNATURE_INPUT_DIGEST_DOMAIN);
  const signatureInput = buildDocumentSignatureInputV2(envelope);
  const result = new Uint8Array(label.length + 1 + signatureInput.length);
  result.set(label, 0);
  result[label.length] = 0;
  result.set(signatureInput, label.length + 1);
  return result;
}

/** Bytes hashed by the human-approval subject's document-input commitment. */
export function buildHumanApprovalDocumentSignatureInputDigestPreimageV1(document) {
  if (!isRecord(document)) throw new TypeError('JACS document must be a plain object');
  const label = encodeUtf8(HUMAN_APPROVAL_DOCUMENT_SIGNATURE_INPUT_DIGEST_DOMAIN);
  const signatureInput = document[DOCUMENT_V2_PLACEMENT_KEY]?.signature === ''
    ? buildDocumentSignatureInputV2(document)
    : buildSignedDocumentSignatureInputV2(document);
  const result = new Uint8Array(label.length + 1 + signatureInput.length);
  result.set(label, 0);
  result[label.length] = 0;
  result.set(signatureInput, label.length + 1);
  return result;
}

/** Exact bytes hashed for the optional native `jacsSha256` checksum. */
export function buildDocumentChecksumInputV1(document) {
  if (!isRecord(document)) throw new TypeError('JACS document must be a plain object');
  const checksumInput = Object.create(null);
  for (const key of Object.keys(document)) {
    if (key !== 'jacsSha256') checksumInput[key] = document[key];
  }
  return encodeUtf8(canonicalizeJson(checksumInput));
}
