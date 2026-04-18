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

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type { SigningKeyPair } from '../types.js';
import { InvalidInputError } from '../errors.js';

export const ALGORITHM_ID = 'ML-DSA-65';
export const PUBLIC_KEY_BYTES = 1952;
export const SECRET_KEY_BYTES = 4032;
export const SIGNATURE_BYTES = 3309;

/**
 * Generate an ML-DSA-65 signing keypair.
 * Uses the library's internal CSPRNG (crypto.getRandomValues).
 */
export function generateSigningKeyPair(): SigningKeyPair {
  const kp = ml_dsa65.keygen();
  return {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
    algorithmId: ALGORITHM_ID,
  };
}

/**
 * Sign a message with an ML-DSA-65 secret key.
 * @param message - Arbitrary-length message to sign.
 * @param secretKey - 4,032-byte ML-DSA-65 secret key.
 * @returns 3,309-byte signature.
 * @throws InvalidInputError if secretKey is wrong size.
 */
export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== SECRET_KEY_BYTES) {
    throw new InvalidInputError(
      `secretKey must be ${String(SECRET_KEY_BYTES)} bytes, got ${String(secretKey.length)}`,
    );
  }
  return ml_dsa65.sign(message, secretKey);
}

/**
 * Verify an ML-DSA-65 signature.
 * @returns true if valid, false if invalid. Never throws for invalid signatures.
 * @throws InvalidInputError if publicKey or signature is wrong size.
 */
export function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (publicKey.length !== PUBLIC_KEY_BYTES) {
    throw new InvalidInputError(
      `publicKey must be ${String(PUBLIC_KEY_BYTES)} bytes, got ${String(publicKey.length)}`,
    );
  }
  if (signature.length !== SIGNATURE_BYTES) {
    throw new InvalidInputError(
      `signature must be ${String(SIGNATURE_BYTES)} bytes, got ${String(signature.length)}`,
    );
  }
  try {
    return ml_dsa65.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
