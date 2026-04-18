/**
 * Shamir Secret Sharing — polynomial split and Lagrange reconstruction.
 * Operates over GF(p) where p = 2^256 - 189.
 *
 * Reference: Shamir (1979) "How to Share a Secret"
 */
/** A raw share: index (x-coordinate) and value (y-coordinate as bytes). */
export interface RawShare {
    readonly index: number;
    readonly value: Uint8Array;
}
/**
 * Split a 32-byte secret into shares using a random polynomial of degree (threshold - 1).
 *
 * @param secret - Exactly 32 bytes.
 * @param threshold - Minimum shares for reconstruction (k). Must be >= 2.
 * @param totalShares - Total shares to generate (n). Must be >= threshold, <= 255.
 * @returns Array of RawShare (index + 32-byte value). No HMAC tags — that's key-split.ts's job.
 */
export declare function generateShares(secret: Uint8Array, threshold: number, totalShares: number): RawShare[];
/**
 * Reconstruct the secret from shares via Lagrange interpolation at x = 0.
 *
 * @param shares - At least threshold shares with unique indexes.
 * @returns The 32-byte reconstructed secret.
 */
export declare function reconstructSecret(shares: readonly RawShare[]): Uint8Array;
//# sourceMappingURL=shamir.d.ts.map