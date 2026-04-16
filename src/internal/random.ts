/**
 * Thin wrapper over globalThis.crypto.getRandomValues for testability.
 * Always produces fresh CSPRNG bytes — never cached, never deterministic in production.
 *
 * This is the ONLY source of randomness in the library. All IVs and keys derive
 * from this path so any future audit can verify one chokepoint.
 */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new Error(`randomBytes: length must be a non-negative integer, got ${String(length)}`);
  }
  const buf = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}
