/**
 * eternis-crypto — audited cryptographic primitives for Eternis.
 *
 * v0.1 public surface: AES-256-GCM authenticated encryption.
 * v0.2 public surface: HPKE key wrapping (hybrid post-quantum default).
 *
 * See README.md for the full usage guide and the three architectural
 * principles this library enforces.
 */
export type { Ciphertext } from './types.js';
export { KeyHandle, generateKey } from './keys.js';
export { encryptChunk, decryptChunk } from './aes-gcm.js';
export type { WrappedKey, MasterKeyPair } from './types.js';
export type { Kem, KemKeyPair, EncapsulationResult } from './kem/kem.js';
export { DHKEM_X25519 } from './kem/dhkem-x25519.js';
export { HYBRID_X25519_MLKEM768 } from './kem/hybrid-kem.js';
export { generateMasterKeyPair, wrapKey, unwrapKey } from './key-wrap.js';
export type { Shard, SplitOptions, SplitResult } from './types.js';
export { splitKey, combineShards } from './sss/key-split.js';
export type { SigningKeyPair, EncryptedShard } from './types.js';
export { generateSigningKeyPair, sign, verify } from './sig/ml-dsa.js';
export { distributeShard, recoverShard } from './sss/shard-encrypt.js';
export type { PreservationPackage } from './types.js';
export { preserve, recover } from './pipeline.js';
export { EternisCryptoError, AuthenticationError, KeyExhaustedError, InvalidInputError, DecapsulationError, KeyWrappingError, ShardAuthenticationError, SignatureVerificationError, } from './errors.js';
//# sourceMappingURL=index.d.ts.map