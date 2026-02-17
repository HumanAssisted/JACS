/**
 * Shared replay-protection helpers for JACS auth middleware.
 *
 * This is intentionally framework-agnostic so Express/Koa can reuse
 * exactly the same validation and replay-cache behavior.
 */
export interface AuthReplayOptions {
    enabled?: boolean;
    maxAgeSeconds?: number;
    clockSkewSeconds?: number;
    cacheTtlSeconds?: number;
}
export interface NormalizedAuthReplayOptions {
    enabled: boolean;
    maxAgeSeconds: number;
    clockSkewSeconds: number;
    cacheTtlSeconds: number;
}
export interface VerificationResultLike {
    signerId?: string;
    timestamp?: string;
}
export declare function normalizeAuthReplayOptions(authReplay: boolean | AuthReplayOptions | undefined): NormalizedAuthReplayOptions;
export declare class InMemoryReplayCache {
    private readonly seen;
    private prune;
    checkAndRemember(key: string, nowMs: number, ttlMs: number): boolean;
}
export declare function checkAuthReplay(rawBody: string, verification: VerificationResultLike, cache: InMemoryReplayCache, options: NormalizedAuthReplayOptions): string | null;
