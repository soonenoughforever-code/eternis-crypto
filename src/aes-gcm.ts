import type { Ciphertext } from './types.js';
import { KeyHandle, _internals } from './keys.js';
import { AuthenticationError, InvalidInputError } from './errors.js';
import { randomBytes } from './internal/random.js';

const IV_BYTES = 12;
const TAG_BYTES = 16;
const TAG_BITS = 128;
const MAX_PLAINTEXT_BYTES = 68_719_476_704; // 2^36 - 32 per NIST SP 800-38D
const MAX_AAD_BYTES = 1_048_576;            // 1 MiB (defensible operational cap)

function validateEncryptInputs(plaintext: Uint8Array, aad: Uint8Array): void {
  if (plaintext.length === 0) {
    throw new InvalidInputError(
      'plaintext must be non-empty (AAD-only authentication is a distinct primitive not exposed here)',
    );
  }
  if (plaintext.length > MAX_PLAINTEXT_BYTES) {
    throw new InvalidInputError(`plaintext exceeds maximum of ${String(MAX_PLAINTEXT_BYTES)} bytes`);
  }
  if (aad.length > MAX_AAD_BYTES) {
    throw new InvalidInputError(`associatedData exceeds maximum of ${String(MAX_AAD_BYTES)} bytes`);
  }
}

function validateDecryptInputs(ct: Ciphertext, aad: Uint8Array): void {
  if (ct.iv.length !== IV_BYTES) {
    throw new InvalidInputError(`iv must be exactly ${String(IV_BYTES)} bytes, got ${String(ct.iv.length)}`);
  }
  if (ct.tag.length !== TAG_BYTES) {
    throw new InvalidInputError(`tag must be exactly ${String(TAG_BYTES)} bytes, got ${String(ct.tag.length)}`);
  }
  if (aad.length > MAX_AAD_BYTES) {
    throw new InvalidInputError(`associatedData exceeds maximum of ${String(MAX_AAD_BYTES)} bytes`);
  }
}

/**
 * Encrypt one chunk with AES-256-GCM.
 *
 * - Generates a fresh random 96-bit IV on every call (never exposed to the caller).
 * - Produces a 128-bit authentication tag.
 * - Increments the per-key invocation counter. Throws KeyExhaustedError at 2^32.
 */
export async function encryptChunk(
  key: KeyHandle,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Promise<Ciphertext> {
  validateEncryptInputs(plaintext, associatedData);  // validate FIRST — don't burn a counter slot on bad input
  const inner = _internals(key);
  inner.counter.increment(); // throws KeyExhaustedError at ceiling

  const iv = randomBytes(IV_BYTES);

  const combined = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as Uint8Array<ArrayBuffer>,
        additionalData: associatedData as Uint8Array<ArrayBuffer>,
        tagLength: TAG_BITS,
      },
      inner.cryptoKey,
      plaintext as Uint8Array<ArrayBuffer>,
    ),
  );

  // Web Crypto returns ciphertext ‖ tag concatenated. Split into the clean three-field form.
  const ciphertext = combined.slice(0, combined.length - TAG_BYTES);
  const tag = combined.slice(combined.length - TAG_BYTES);

  return { iv, ciphertext, tag };
}

/**
 * Decrypt one chunk.
 *
 * Throws AuthenticationError on any tag mismatch — wrong key, wrong associated
 * data, tampered ciphertext, or tampered IV.
 */
export async function decryptChunk(
  key: KeyHandle,
  ct: Ciphertext,
  associatedData: Uint8Array,
): Promise<Uint8Array> {
  validateDecryptInputs(ct, associatedData);
  const inner = _internals(key);

  const combined = new Uint8Array(ct.ciphertext.length + ct.tag.length);
  combined.set(ct.ciphertext, 0);
  combined.set(ct.tag, ct.ciphertext.length);

  try {
    const plaintextBuf = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ct.iv as Uint8Array<ArrayBuffer>,
        additionalData: associatedData as Uint8Array<ArrayBuffer>,
        tagLength: TAG_BITS,
      },
      inner.cryptoKey,
      combined,
    );
    return new Uint8Array(plaintextBuf);
  } catch (cause) {
    throw new AuthenticationError(
      'decryption failed (tag mismatch: wrong key, wrong associated data, or tampered ciphertext/iv)',
      { cause },
    );
  }
}

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
export async function _encryptChunkWithIV(
  key: KeyHandle,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
  iv: Uint8Array,
): Promise<Ciphertext> {
  if (iv.length !== IV_BYTES) {
    throw new InvalidInputError(`iv must be exactly ${String(IV_BYTES)} bytes, got ${String(iv.length)}`);
  }
  if (plaintext.length > MAX_PLAINTEXT_BYTES) {
    throw new InvalidInputError(`plaintext exceeds maximum of ${String(MAX_PLAINTEXT_BYTES)} bytes`);
  }
  if (associatedData.length > MAX_AAD_BYTES) {
    throw new InvalidInputError(`associatedData exceeds maximum of ${String(MAX_AAD_BYTES)} bytes`);
  }

  const inner = _internals(key);

  const combined = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer>, additionalData: associatedData as Uint8Array<ArrayBuffer>, tagLength: TAG_BITS },
      inner.cryptoKey,
      plaintext as Uint8Array<ArrayBuffer>,
    ),
  );
  const ciphertext = combined.slice(0, combined.length - TAG_BYTES);
  const tag = combined.slice(combined.length - TAG_BYTES);
  return { iv, ciphertext, tag };
}
