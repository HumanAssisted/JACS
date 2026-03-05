/**
 * Emit a deprecation warning for a method alias.
 *
 * Only fires when `process.env.JACS_SHOW_DEPRECATIONS` is truthy, and at most
 * once per unique `oldName` per process lifetime.
 *
 * @param oldName  - The deprecated method name.
 * @param newName  - The replacement method name.
 */
export declare function warnDeprecated(oldName: string, newName: string): void;
