/**
 * ML-DSA-65 digital signature module (NIST FIPS 204, Security Level 3).
 *
 * Thin wrapper around @noble/post-quantum/ml-dsa.js.
 * All functions are synchronous — ML-DSA is pure computation, no Web Crypto.
 *
 * References:
 * - NIST FIPS 204 (August 2024) — ML-DSA standard
 * - IETF draft-ietf-pquip-pqc-engineers — PQC for engineers
 */
import type { SigningKeyPair } from '../types.js';
export declare const ALGORITHM_ID = "ML-DSA-65";
export declare const PUBLIC_KEY_BYTES = 1952;
export declare const SECRET_KEY_BYTES = 4032;
export declare const SIGNATURE_BYTES = 3309;
/**
 * Generate an ML-DSA-65 signing keypair.
 * Uses the library's internal CSPRNG (crypto.getRandomValues).
 */
export declare function generateSigningKeyPair(): SigningKeyPair;
/**
 * Sign a message with an ML-DSA-65 secret key.
 * @param message - Arbitrary-length message to sign.
 * @param secretKey - 4,032-byte ML-DSA-65 secret key.
 * @returns 3,309-byte signature.
 * @throws InvalidInputError if secretKey is wrong size.
 */
export declare function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
/**
 * Verify an ML-DSA-65 signature.
 * @returns true if valid, false if invalid. Never throws for invalid signatures.
 * @throws InvalidInputError if publicKey or signature is wrong size.
 */
export declare function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
//# sourceMappingURL=ml-dsa.d.ts.map