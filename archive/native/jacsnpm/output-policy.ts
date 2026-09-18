/**
 * Shared fail-closed policy for adapter outputs.
 *
 * Deliberately accept `unknown`: JavaScript callers can bypass TypeScript, so
 * truthy strings or objects must never enable an unsigned-output fallback.
 */
export function allowUnsignedOutput(value: unknown, strict: unknown = false): boolean {
  return strict !== true && value === true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Require the minimum portable-v2 signed-document shape shared by every
 * signing adapter. This is structural validation, not cryptographic
 * verification, but it prevents empty, legacy-v1, and incomplete objects from
 * being presented as newly signed output.
 */
export function requirePortableV2SignedDocument(
  value: unknown,
  context: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new TypeError(`${context} did not return a portable signed document`);
  }

  const signature = value.jacsSignature;
  const signerId = isRecord(signature) ? signature.agentID ?? signature.agentId : undefined;
  if (
    !isNonEmptyString(value.jacsId)
    || !isNonEmptyString(value.jacsVersion)
    || !isRecord(signature)
    || signature.signatureContentVersion !== 'jacs-signature-v2'
    || !isNonEmptyString(signature.signature)
    || !isNonEmptyString(signerId)
    || !isNonEmptyString(signature.agentVersion)
    || !isNonEmptyString(signature.publicKeyHash)
    || !isNonEmptyString(signature.date)
  ) {
    throw new TypeError(`${context} did not return complete portable v2 signature metadata`);
  }

  return value;
}

/** Return the portable signed document or reject malformed binding output. */
export function requireSignedRaw(value: unknown, context: string): string {
  if (!isRecord(value)) {
    throw new TypeError(`${context} did not return a portable signed document`);
  }

  const raw = value.raw;
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw new TypeError(`${context} did not return a portable signed document in raw`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new TypeError(`${context} did not return a JSON portable signed document`);
  }
  requirePortableV2SignedDocument(parsed, context);
  return raw;
}

/** Require a non-empty transport envelope before forwarding it. */
export function requireSignedEnvelope(value: unknown, context: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError(`${context} did not return a signed envelope`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new TypeError(`${context} did not return a JSON signed envelope`);
  }
  requirePortableV2SignedDocument(parsed, context);
  return value;
}
