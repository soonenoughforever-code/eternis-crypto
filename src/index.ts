/**
 * eternis-crypto — audited cryptographic primitives for Eternis.
 *
 * v0.1 public surface: AES-256-GCM authenticated encryption.
 *
 * See README.md for the full usage guide and the three architectural
 * principles this library enforces.
 */

export type { Ciphertext } from './types.js';
export { KeyHandle, generateKey } from './keys.js';
export { encryptChunk, decryptChunk } from './aes-gcm.js';
export {
  EternisCryptoError,
  AuthenticationError,
  KeyExhaustedError,
  InvalidInputError,
} from './errors.js';
