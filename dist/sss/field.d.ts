/**
 * Prime field arithmetic over GF(p) where p = 2^256 - 189.
 * This is the largest 256-bit prime. All operations produce
 * results in [0, p). Used as the substrate for Shamir SSS.
 *
 * SECURITY - NOT CONSTANT TIME (finding F2, open):
 * These operations use native JavaScript BigInt, whose execution time and
 * allocation depend on operand magnitude/limb-count; `mod` also branches on the
 * sign of an intermediate. When these run on SECRET values (share y-coordinates
 * and the reconstructed DEK in shamir.ts), a co-resident or otherwise
 * high-resolution timing observer can in principle learn information about the
 * secret. Reconstruction is single-shot per package (not an adaptive oracle),
 * and the Lagrange denominators are computed on PUBLIC indices, which bounds the
 * practical leak, but this does not meet a constant-time bar.
 *
 * Mitigation status: run reconstruction only in a trusted, non-co-resident
 * context. A constant-time replacement (vetted GF(2^8) byte-wise SSS or blinded
 * interpolation) is deferred pending cryptographer review; do not add blinding
 * here without that review, as an incorrect countermeasure gives false comfort.
 */
/** The field prime: 2^256 - 189. */
export declare const P: bigint;
/** Reduce a bigint into [0, P). Handles negative inputs. */
export declare function mod(a: bigint): bigint;
/** (a + b) mod P */
export declare function add(a: bigint, b: bigint): bigint;
/** (a - b) mod P — never negative */
export declare function sub(a: bigint, b: bigint): bigint;
/** (a * b) mod P */
export declare function mul(a: bigint, b: bigint): bigint;
/**
 * Modular exponentiation via square-and-multiply.
 * Computes base^exp mod P.
 */
export declare function pow(base: bigint, exp: bigint): bigint;
/**
 * Multiplicative inverse via Fermat's little theorem: a^(P-2) mod P.
 * Throws if a === 0 (no inverse exists).
 */
export declare function inv(a: bigint): bigint;
/** Convert a 32-byte big-endian Uint8Array to a BigInt. */
export declare function bytesToBigInt(b: Uint8Array): bigint;
/** Convert a BigInt to a 32-byte big-endian Uint8Array, zero-padded. */
export declare function bigIntToBytes(n: bigint): Uint8Array;
//# sourceMappingURL=field.d.ts.map