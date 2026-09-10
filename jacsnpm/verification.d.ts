/**
 * Fail-closed helpers for presenting verification results.
 *
 * Legacy-v1 compatibility authenticates payload fields, not signer/key/time
 * metadata. Centralizing this rule prevents high-level APIs from accidentally
 * presenting parsed legacy fields as authenticated attribution.
 */
export declare const V2_SIGNATURE_CONTENT_VERSION = "jacs-signature-v2";
/**
 * Require an exact successful result from a native cryptographic verifier.
 * High-level wrappers must never infer success from completion, truthiness, or
 * a malformed binding return value.
 */
export declare function requireLiteralTrueVerification(result: unknown, context: string): void;
export interface AuthenticatedSignatureMetadata {
    signerId: string;
    publicKeyHash: string;
    timestamp: string;
}
export declare function authenticatedSignatureMetadata(document: unknown): AuthenticatedSignatureMetadata;
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
export declare function normalizeAgreementStatus(result: unknown): NormalizedAgreementStatus;
/**
 * Normalize an attestation result and recompute its security aggregate from
 * exact booleans. Missing, string, numeric, or contradictory flags fail closed.
 */
export declare function normalizeAttestationVerificationResult(result: unknown): Record<string, unknown>;
