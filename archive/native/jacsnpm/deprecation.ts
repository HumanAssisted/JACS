/**
 * JACS Deprecation Warning Utility
 *
 * Emits console.warn messages for deprecated methods when the
 * `JACS_SHOW_DEPRECATIONS` environment variable is set.
 *
 * Warnings are emitted at most once per method name per process to avoid
 * flooding logs.
 */

const _warned = new Set<string>();

/**
 * Emit a deprecation warning for a method alias.
 *
 * Only fires when `process.env.JACS_SHOW_DEPRECATIONS` is truthy, and at most
 * once per unique `oldName` per process lifetime.
 *
 * @param oldName  - The deprecated method name.
 * @param newName  - The replacement method name.
 */
export function warnDeprecated(oldName: string, newName: string): void {
  if (process.env.JACS_SHOW_DEPRECATIONS && !_warned.has(oldName)) {
    _warned.add(oldName);
    console.warn(`[JACS] ${oldName}() is deprecated, use ${newName}() instead`);
  }
}
