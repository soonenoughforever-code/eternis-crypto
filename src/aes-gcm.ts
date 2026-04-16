import type { Ciphertext } from './types.js';
import { KeyHandle, _internals } from './keys.js';
import { AuthenticationError } from './errors.js';
import { randomBytes } from './internal/random.js';

const IV_BYTES = 12;
const TAG_BYTES = 16;
const TAG_BITS = 128;

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
