/**
 * eternis-crypto — audited cryptographic primitives for Eternis.
 *
 * v0.1 public surface: AES-256-GCM authenticated encryption.
 * v0.2 public surface: HPKE key wrapping (hybrid post-quantum default).
 *
 * See README.md for the full usage guide and the three architectural
 * principles this library enforces.
 */
export { KeyHandle, generateKey } from './keys.js';
export { encryptChunk, decryptChunk } from './aes-gcm.js';
export { DHKEM_X25519 } from './kem/dhkem-x25519.js';
export { HYBRID_X25519_MLKEM768 } from './kem/hybrid-kem.js';
export { generateMasterKeyPair, wrapKey, unwrapKey } from './key-wrap.js';
export { splitKey, combineShards } from './sss/key-split.js';
export { generateSigningKeyPair, sign, verify } from './sig/ml-dsa.js';
export { distributeShard, recoverShard } from './sss/shard-encrypt.js';
export { preserve, recover } from './pipeline.js';
// Shared errors
export { EternisCryptoError, AuthenticationError, KeyExhaustedError, InvalidInputError, DecapsulationError, KeyWrappingError, ShardAuthenticationError, SignatureVerificationError, } from './errors.js';
//# sourceMappingURL=index.js.map