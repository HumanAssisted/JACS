export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export declare const DOCUMENT_V2_SIGNATURE_PROFILE = "jacs-document-v2";
export declare const DOCUMENT_V2_PLACEMENT_KEY = "jacsSignature";
export declare const HAI_SIGNATURE_INPUT_DIGEST_DOMAIN = "JACS-HAI-SIGNATURE-INPUT-V1";

/** RFC 8785/JCS canonical JSON used by the JACS v2 signature family. */
export declare function canonicalizeJson(value: unknown): string;

/** UTF-8 encoding without requiring a global TextEncoder. */
export declare function encodeUtf8(value: string): Uint8Array;

/** Recompute the exact document-v2 signature input from a complete envelope. */
export declare function buildDocumentSignatureInputV2(envelope: unknown): Uint8Array;

/** Build the exact domain-labeled bytes hashed by HAI prepared intents. */
export declare function buildHaiSignatureInputDigestPreimageV1(envelope: unknown): Uint8Array;
