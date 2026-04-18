/**
 * Prime field arithmetic over GF(p) where p = 2^256 - 189.
 * This is the largest 256-bit prime. All operations produce
 * results in [0, p). Used as the substrate for Shamir SSS.
 */
/** The field prime: 2^256 - 189. */
export const P = 2n ** 256n - 189n;
/** Reduce a bigint into [0, P). Handles negative inputs. */
export function mod(a) {
    const r = a % P;
    return r < 0n ? r + P : r;
}
/** (a + b) mod P */
export function add(a, b) {
    return mod(a + b);
}
/** (a - b) mod P — never negative */
export function sub(a, b) {
    return mod(a - b);
}
/** (a * b) mod P */
export function mul(a, b) {
    return mod(a * b);
}
/**
 * Modular exponentiation via square-and-multiply.
 * Computes base^exp mod P.
 */
export function pow(base, exp) {
    base = mod(base);
    let result = 1n;
    while (exp > 0n) {
        if (exp & 1n) {
            result = mul(result, base);
        }
        base = mul(base, base);
        exp >>= 1n;
    }
    return result;
}
/**
 * Multiplicative inverse via Fermat's little theorem: a^(P-2) mod P.
 * Throws if a === 0 (no inverse exists).
 */
export function inv(a) {
    a = mod(a);
    if (a === 0n) {
        throw new Error('Cannot compute inverse of zero');
    }
    return pow(a, P - 2n);
}
/** Convert a 32-byte big-endian Uint8Array to a BigInt. */
export function bytesToBigInt(b) {
    let result = 0n;
    for (let i = 0; i < b.length; i++) {
        result = (result << 8n) | BigInt(b[i]);
    }
    return result;
}
/** Convert a BigInt to a 32-byte big-endian Uint8Array, zero-padded. */
export function bigIntToBytes(n) {
    const bytes = new Uint8Array(32);
    let val = n;
    for (let i = 31; i >= 0; i--) {
        bytes[i] = Number(val & 0xffn);
        val >>= 8n;
    }
    return bytes;
}
//# sourceMappingURL=field.js.map