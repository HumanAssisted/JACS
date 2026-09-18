"use strict";
/**
 * Shared replay-protection helpers for JACS auth middleware.
 *
 * This is intentionally framework-agnostic so Express/Koa can reuse
 * exactly the same validation and replay-cache behavior.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.InMemoryReplayCache = void 0;
exports.normalizeAuthReplayOptions = normalizeAuthReplayOptions;
exports.checkAuthReplay = checkAuthReplay;
const DEFAULT_MAX_AGE_SECONDS = 30;
const DEFAULT_CLOCK_SKEW_SECONDS = 5;
function normalizePositiveInt(value, fallback) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        return fallback;
    }
    return Math.floor(value);
}
function normalizeAuthReplayOptions(authReplay) {
    if (authReplay === true) {
        const ttl = DEFAULT_MAX_AGE_SECONDS + DEFAULT_CLOCK_SKEW_SECONDS;
        return {
            enabled: true,
            maxAgeSeconds: DEFAULT_MAX_AGE_SECONDS,
            clockSkewSeconds: DEFAULT_CLOCK_SKEW_SECONDS,
            cacheTtlSeconds: ttl,
        };
    }
    if (authReplay === undefined || authReplay === false) {
        const ttl = DEFAULT_MAX_AGE_SECONDS + DEFAULT_CLOCK_SKEW_SECONDS;
        return {
            enabled: false,
            maxAgeSeconds: DEFAULT_MAX_AGE_SECONDS,
            clockSkewSeconds: DEFAULT_CLOCK_SKEW_SECONDS,
            cacheTtlSeconds: ttl,
        };
    }
    const maxAgeSeconds = normalizePositiveInt(authReplay.maxAgeSeconds, DEFAULT_MAX_AGE_SECONDS);
    const clockSkewSeconds = normalizePositiveInt(authReplay.clockSkewSeconds, DEFAULT_CLOCK_SKEW_SECONDS);
    const defaultTtl = maxAgeSeconds + clockSkewSeconds;
    const cacheTtlSeconds = normalizePositiveInt(authReplay.cacheTtlSeconds, defaultTtl > 0 ? defaultTtl : 1);
    return {
        enabled: authReplay.enabled !== false,
        maxAgeSeconds,
        clockSkewSeconds,
        cacheTtlSeconds: cacheTtlSeconds > 0 ? cacheTtlSeconds : 1,
    };
}
class InMemoryReplayCache {
    constructor() {
        this.seen = new Map();
    }
    prune(nowMs) {
        for (const [key, expiresAt] of this.seen.entries()) {
            if (expiresAt <= nowMs) {
                this.seen.delete(key);
            }
        }
    }
    checkAndRemember(key, nowMs, ttlMs) {
        this.prune(nowMs);
        const existingExpiry = this.seen.get(key);
        if (existingExpiry && existingExpiry > nowMs) {
            return true;
        }
        this.seen.set(key, nowMs + Math.max(ttlMs, 1000));
        return false;
    }
}
exports.InMemoryReplayCache = InMemoryReplayCache;
function parseEnvelope(rawBody) {
    try {
        const parsed = JSON.parse(rawBody);
        return parsed && typeof parsed === 'object' ? parsed : null;
    }
    catch {
        return null;
    }
}
function parseTimestamp(timestamp) {
    const ms = Date.parse(timestamp);
    if (!Number.isFinite(ms)) {
        return null;
    }
    return ms;
}
function checkAuthReplay(rawBody, verification, cache, options) {
    const envelope = parseEnvelope(rawBody);
    if (!envelope) {
        return 'replay protection requires a valid JSON JACS document';
    }
    const signerId = verification.signerId ||
        envelope.jacsSignature?.agentID ||
        '';
    const timestamp = verification.timestamp ||
        envelope.jacsSignature?.date ||
        '';
    const signature = envelope.jacsSignature?.signature || '';
    if (!signerId) {
        return 'replay protection requires signerId';
    }
    if (!timestamp) {
        return 'replay protection requires signature timestamp';
    }
    if (!signature) {
        return 'replay protection requires signature value';
    }
    const tsMs = parseTimestamp(timestamp);
    if (tsMs === null) {
        return `replay protection found invalid timestamp '${timestamp}'`;
    }
    const nowMs = Date.now();
    const maxSkewMs = options.clockSkewSeconds * 1000;
    const maxAgeMs = options.maxAgeSeconds * 1000;
    if (tsMs > nowMs + maxSkewMs) {
        return 'replay protection rejected request with future timestamp';
    }
    if (tsMs < nowMs - maxAgeMs) {
        return 'replay protection rejected expired request timestamp';
    }
    const replayKey = `${signerId}:${signature}`;
    const ttlMs = options.cacheTtlSeconds * 1000;
    if (cache.checkAndRemember(replayKey, nowMs, ttlMs)) {
        return 'replay protection detected replayed signature';
    }
    return null;
}
//# sourceMappingURL=auth-replay.js.map