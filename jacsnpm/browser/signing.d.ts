export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export declare const DOCUMENT_V2_SIGNATURE_PROFILE = "jacs-document-v2";
export declare const DOCUMENT_V2_PLACEMENT_KEY = "jacsSignature";
export declare const HAI_SIGNATURE_INPUT_DIGEST_DOMAIN = "JACS-HAI-SIGNATURE-INPUT-V1";
export declare const HUMAN_APPROVAL_DOCUMENT_SIGNATURE_INPUT_DIGEST_DOMAIN = "JACS-HUMAN-APPROVAL-DOCUMENT-SIGNATURE-INPUT-V1";

/** RFC 8785/JCS canonical JSON used by the JACS v2 signature family. */
export declare function canonicalizeJson(value: unknown): string;

/** UTF-8 encoding without requiring a global TextEncoder. */
export declare function encodeUtf8(value: string): Uint8Array;

/** Recompute the exact document-v2 signature input from a complete envelope. */
export declare function buildDocumentSignatureInputV2(envelope: unknown): Uint8Array;

/** Recompute a completed document's exact v2 signature input. */
export declare function buildSignedDocumentSignatureInputV2(document: unknown): Uint8Array;

/** Build the exact domain-labeled bytes hashed by HAI prepared intents. */
export declare function buildHaiSignatureInputDigestPreimageV1(envelope: unknown): Uint8Array;

/** Build the exact domain-labeled bytes used by a human-approval subject. */
export declare function buildHumanApprovalDocumentSignatureInputDigestPreimageV1(document: unknown): Uint8Array;

/** Build exact bytes for the optional native `jacsSha256` checksum. */
export declare function buildDocumentChecksumInputV1(document: unknown): Uint8Array;
