"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.warnDeprecated = warnDeprecated;

const _warned = new Set();

/**
 * Emit a deprecation warning for a method alias.
 *
 * Only fires when `process.env.JACS_SHOW_DEPRECATIONS` is truthy, and at most
 * once per unique `oldName` per process lifetime.
 *
 * @param {string} oldName  - The deprecated method name.
 * @param {string} newName  - The replacement method name.
 */
function warnDeprecated(oldName, newName) {
  if (process.env.JACS_SHOW_DEPRECATIONS && !_warned.has(oldName)) {
    _warned.add(oldName);
    console.warn(`[JACS] ${oldName}() is deprecated, use ${newName}() instead`);
  }
}
