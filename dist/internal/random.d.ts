/**
 * Thin wrapper over globalThis.crypto.getRandomValues for testability.
 * Always produces fresh CSPRNG bytes — never cached, never deterministic in production.
 *
 * This is the ONLY source of randomness in the library. All IVs and keys derive
 * from this path so any future audit can verify one chokepoint.
 */
export declare function randomBytes(length: number): Uint8Array;
//# sourceMappingURL=random.d.ts.map