/**
 * Fail-closed helpers for presenting verification results.
 *
 * Legacy-v1 compatibility authenticates payload fields, not signer/key/time
 * metadata. Centralizing this rule prevents high-level APIs from accidentally
 * presenting parsed legacy fields as authenticated attribution.
 */

export const V2_SIGNATURE_CONTENT_VERSION = 'jacs-signature-v2';

/**
 * Require an exact successful result from a native cryptographic verifier.
 * High-level wrappers must never infer success from completion, truthiness, or
 * a malformed binding return value.
 */
export function requireLiteralTrueVerification(
  result: unknown,
  context: string,
): void {
  if (result !== true) {
    throw new Error(`${context} did not return literal true`);
  }
}

export interface AuthenticatedSignatureMetadata {
  signerId: string;
  publicKeyHash: string;
  timestamp: string;
}

export function authenticatedSignatureMetadata(
  document: unknown,
): AuthenticatedSignatureMetadata {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    return { signerId: '', publicKeyHash: '', timestamp: '' };
  }
  const signature = (document as Record<string, unknown>).jacsSignature;
  if (!signature || typeof signature !== 'object' || Array.isArray(signature)) {
    return { signerId: '', publicKeyHash: '', timestamp: '' };
  }
  const metadata = signature as Record<string, unknown>;
  if (metadata.signatureContentVersion !== V2_SIGNATURE_CONTENT_VERSION) {
    return { signerId: '', publicKeyHash: '', timestamp: '' };
  }

  const signerId = metadata.agentId ?? metadata.agentID;
  return {
    signerId: typeof signerId === 'string' ? signerId : '',
    publicKeyHash: typeof metadata.publicKeyHash === 'string' ? metadata.publicKeyHash : '',
    timestamp: typeof metadata.date === 'string' ? metadata.date : '',
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export interface NormalizedAgreementStatus {
  complete: boolean;
  signers: Array<{
    agentId: string;
    signed: boolean;
    signedAt?: string;
  }>;
  pending: string[];
}

/** Normalize agreement status without allowing JSON truthiness to grant completion. */
export function normalizeAgreementStatus(result: unknown): NormalizedAgreementStatus {
  if (!isRecord(result)) {
    throw new Error('Agreement status result must be a JSON object');
  }
  const rawSigners = result.signers;
  const signersWellFormed = Array.isArray(rawSigners)
    && rawSigners.every((signer) => isRecord(signer) && typeof signer.signed === 'boolean');
  const signers = Array.isArray(rawSigners)
    ? rawSigners.map((value) => {
      const signer = isRecord(value) ? value : {};
      const rawAgentId = signer.agentId ?? signer.agent_id;
      const rawSignedAt = signer.signedAt ?? signer.signed_at;
      return {
        agentId: typeof rawAgentId === 'string' ? rawAgentId : '',
        signed: signer.signed === true,
        ...(typeof rawSignedAt === 'string' ? { signedAt: rawSignedAt } : {}),
      };
    })
    : [];
  const pendingWellFormed = Array.isArray(result.pending)
    && result.pending.every((agentId) => typeof agentId === 'string');
  const pending = pendingWellFormed ? result.pending as string[] : [];
  return {
    complete: result.complete === true && signersWellFormed && pendingWellFormed,
    signers,
    pending,
  };
}

/**
 * Normalize an attestation result and recompute its security aggregate from
 * exact booleans. Missing, string, numeric, or contradictory flags fail closed.
 */
export function normalizeAttestationVerificationResult(
  result: unknown,
): Record<string, unknown> {
  if (!isRecord(result)) {
    throw new Error('Attestation verification result must be a JSON object');
  }
  const normalized: Record<string, unknown> = { ...result };

  const crypto = isRecord(result.crypto) ? { ...result.crypto } : {};
  const signatureValid = crypto.signatureValid === true;
  const hashValid = crypto.hashValid === true;
  crypto.signatureValid = signatureValid;
  crypto.hashValid = hashValid;
  normalized.crypto = crypto;
  const cryptoValid = signatureValid && hashValid;

  const rawEvidence = result.evidence;
  const evidenceWellFormed = Array.isArray(rawEvidence);
  const evidence = evidenceWellFormed
    ? rawEvidence.map((value: unknown) => {
      const item = isRecord(value) ? { ...value } : {};
      item.digestValid = item.digestValid === true;
      item.freshnessValid = item.freshnessValid === true;
      return item;
    })
    : [];
  normalized.evidence = evidence;
  const evidenceValid = evidenceWellFormed
    && evidence.every(
      (item: Record<string, unknown>) => (
        item.digestValid === true && item.freshnessValid === true
      ),
    );

  let chainValid = true;
  if (result.chain === null || result.chain === undefined) {
    normalized.chain = null;
  } else {
    const chain = isRecord(result.chain) ? { ...result.chain } : {};
    const rawLinks = chain.links;
    const linksWellFormed = Array.isArray(rawLinks);
    const links = linksWellFormed
      ? rawLinks.map((value: unknown) => {
        const link = isRecord(value) ? { ...value } : {};
        link.valid = link.valid === true;
        return link;
      })
      : [];
    chain.links = links;
    const normalizedChainValid = chain.valid === true
      && linksWellFormed
      && links.every((link: Record<string, unknown>) => link.valid === true);
    chain.valid = normalizedChainValid;
    normalized.chain = chain;
    chainValid = normalizedChainValid;
  }

  normalized.valid = result.valid === true
    && cryptoValid
    && evidenceValid
    && chainValid;
  return normalized;
}
