import type { Ciphertext } from './types.js';
import { KeyHandle } from './keys.js';
/**
 * Encrypt one chunk with AES-256-GCM.
 *
 * - Generates a fresh random 96-bit IV on every call (never exposed to the caller).
 * - Produces a 128-bit authentication tag.
 * - Increments the per-key invocation counter. Throws KeyExhaustedError at 2^32.
 */
export declare function encryptChunk(key: KeyHandle, plaintext: Uint8Array, associatedData: Uint8Array): Promise<Ciphertext>;
/**
 * Decrypt one chunk.
 *
 * Throws AuthenticationError on any tag mismatch — wrong key, wrong associated
 * data, tampered ciphertext, or tampered IV.
 */
export declare function decryptChunk(key: KeyHandle, ct: Ciphertext, associatedData: Uint8Array): Promise<Uint8Array>;
/**
 * Test-only: encrypt with a caller-supplied IV. Used exclusively for NIST CAVP
 * vector verification where the test expects a specific IV. NEVER exposed from
 * src/index.ts and must NEVER be called by production code.
 *
 * Skips:
 *   - the "IV is always internal" rule (that's the whole point of this function)
 *   - the empty-plaintext rejection (NIST has PTlen=0 vectors)
 *   - the invocation counter (vectors are not real-world encryptions)
 *
 * Still enforces: IV length == 12, AAD cap, plaintext cap.
 */
export declare function _encryptChunkWithIV(key: KeyHandle, plaintext: Uint8Array, associatedData: Uint8Array, iv: Uint8Array): Promise<Ciphertext>;
//# sourceMappingURL=aes-gcm.d.ts.map