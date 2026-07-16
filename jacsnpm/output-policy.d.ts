/**
 * Shared fail-closed policy for adapter outputs.
 *
 * Deliberately accept `unknown`: JavaScript callers can bypass TypeScript, so
 * truthy strings or objects must never enable an unsigned-output fallback.
 */
export declare function allowUnsignedOutput(value: unknown, strict?: unknown): boolean;
/**
 * Require the minimum portable-v2 signed-document shape shared by every
 * signing adapter. This is structural validation, not cryptographic
 * verification, but it prevents empty, legacy-v1, and incomplete objects from
 * being presented as newly signed output.
 */
export declare function requirePortableV2SignedDocument(value: unknown, context: string): Record<string, unknown>;
/** Return the portable signed document or reject malformed binding output. */
export declare function requireSignedRaw(value: unknown, context: string): string;
/** Require a non-empty transport envelope before forwarding it. */
export declare function requireSignedEnvelope(value: unknown, context: string): string;
