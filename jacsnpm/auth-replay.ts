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

interface SignedEnvelopeLike {
  jacsSignature?: {
    agentID?: string;
    date?: string;
    signature?: string;
  };
}

const DEFAULT_MAX_AGE_SECONDS = 30;
const DEFAULT_CLOCK_SKEW_SECONDS = 5;

function normalizePositiveInt(value: unknown, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    return fallback;
  }
  return Math.floor(value);
}

export function normalizeAuthReplayOptions(
  authReplay: boolean | AuthReplayOptions | undefined,
): NormalizedAuthReplayOptions {
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

  const maxAgeSeconds = normalizePositiveInt(
    authReplay.maxAgeSeconds,
    DEFAULT_MAX_AGE_SECONDS,
  );
  const clockSkewSeconds = normalizePositiveInt(
    authReplay.clockSkewSeconds,
    DEFAULT_CLOCK_SKEW_SECONDS,
  );
  const defaultTtl = maxAgeSeconds + clockSkewSeconds;
  const cacheTtlSeconds = normalizePositiveInt(
    authReplay.cacheTtlSeconds,
    defaultTtl > 0 ? defaultTtl : 1,
  );

  return {
    enabled: authReplay.enabled !== false,
    maxAgeSeconds,
    clockSkewSeconds,
    cacheTtlSeconds: cacheTtlSeconds > 0 ? cacheTtlSeconds : 1,
  };
}

export class InMemoryReplayCache {
  private readonly seen = new Map<string, number>();

  private prune(nowMs: number): void {
    for (const [key, expiresAt] of this.seen.entries()) {
      if (expiresAt <= nowMs) {
        this.seen.delete(key);
      }
    }
  }

  public checkAndRemember(key: string, nowMs: number, ttlMs: number): boolean {
    this.prune(nowMs);

    const existingExpiry = this.seen.get(key);
    if (existingExpiry && existingExpiry > nowMs) {
      return true;
    }

    this.seen.set(key, nowMs + Math.max(ttlMs, 1000));
    return false;
  }
}

function parseEnvelope(rawBody: string): SignedEnvelopeLike | null {
  try {
    const parsed = JSON.parse(rawBody);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function parseTimestamp(timestamp: string): number | null {
  const ms = Date.parse(timestamp);
  if (!Number.isFinite(ms)) {
    return null;
  }
  return ms;
}

export function checkAuthReplay(
  rawBody: string,
  verification: VerificationResultLike,
  cache: InMemoryReplayCache,
  options: NormalizedAuthReplayOptions,
): string | null {
  const envelope = parseEnvelope(rawBody);
  if (!envelope) {
    return 'replay protection requires a valid JSON JACS document';
  }

  const signerId =
    verification.signerId ||
    envelope.jacsSignature?.agentID ||
    '';
  const timestamp =
    verification.timestamp ||
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
