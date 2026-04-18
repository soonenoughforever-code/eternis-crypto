/**
 * Shamir Secret Sharing — polynomial split and Lagrange reconstruction.
 * Operates over GF(p) where p = 2^256 - 189.
 *
 * Reference: Shamir (1979) "How to Share a Secret"
 */
import { mod, add, sub, mul, inv, bytesToBigInt, bigIntToBytes } from './field.js';
/**
 * Evaluate polynomial q(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[k-1]*x^(k-1)
 * at the given point using Horner's method.
 */
function evaluatePolynomial(coeffs, x) {
    let result = 0n;
    for (let i = coeffs.length - 1; i >= 0; i--) {
        result = add(mul(result, x), coeffs[i]);
    }
    return result;
}
/**
 * Split a 32-byte secret into shares using a random polynomial of degree (threshold - 1).
 *
 * @param secret - Exactly 32 bytes.
 * @param threshold - Minimum shares for reconstruction (k). Must be >= 2.
 * @param totalShares - Total shares to generate (n). Must be >= threshold, <= 255.
 * @returns Array of RawShare (index + 32-byte value). No HMAC tags — that's key-split.ts's job.
 */
export function generateShares(secret, threshold, totalShares) {
    const s = bytesToBigInt(secret);
    // Build polynomial: q(x) = s + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
    const coeffs = [mod(s)];
    for (let i = 1; i < threshold; i++) {
        const randBytes = new Uint8Array(32);
        globalThis.crypto.getRandomValues(randBytes);
        coeffs.push(mod(bytesToBigInt(randBytes)));
    }
    // Evaluate at x = 1, 2, ..., totalShares
    const shares = [];
    for (let i = 1; i <= totalShares; i++) {
        const y = evaluatePolynomial(coeffs, BigInt(i));
        shares.push({ index: i, value: bigIntToBytes(y) });
    }
    return shares;
}
/**
 * Reconstruct the secret from shares via Lagrange interpolation at x = 0.
 *
 * @param shares - At least threshold shares with unique indexes.
 * @returns The 32-byte reconstructed secret.
 */
export function reconstructSecret(shares) {
    const points = shares.map((s) => ({
        x: BigInt(s.index),
        y: bytesToBigInt(s.value),
    }));
    let secret = 0n;
    for (let i = 0; i < points.length; i++) {
        const { x: xi, y: yi } = points[i];
        // Compute Lagrange basis polynomial L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
        let numerator = 1n;
        let denominator = 1n;
        for (let j = 0; j < points.length; j++) {
            if (i === j)
                continue;
            const xj = points[j].x;
            numerator = mul(numerator, sub(0n, xj)); // (0 - x_j)
            denominator = mul(denominator, sub(xi, xj)); // (x_i - x_j)
        }
        const lagrangeCoeff = mul(numerator, inv(denominator));
        secret = add(secret, mul(yi, lagrangeCoeff));
    }
    return bigIntToBytes(secret);
}
//# sourceMappingURL=shamir.js.map