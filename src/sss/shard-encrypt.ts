/**
 * Shard encryption for custodian distribution.
 *
 * distributeShard() — sign a shard with the owner's ML-DSA-65 key,
 *   then encrypt under the custodian's HPKE public key.
 * recoverShard() — decrypt with the custodian's HPKE private key,
 *   then verify the owner's ML-DSA-65 signature.
 *
 * References:
 * - PreVeil (2024) Security Whitepaper — authenticated shard encryption
 * - NIST FIPS 204 — ML-DSA-65 post-quantum signatures
 * - RFC 9180 — HPKE Base mode encryption
 */

import type { Kem } from '../kem/kem.js';
import type { Shard, EncryptedShard } from '../types.js';
import { HYBRID_X25519_MLKEM768 } from '../kem/hybrid-kem.js';
import { sealBase, openBase } from '../hpke.js';
import {
  sign,
  verify,
  ALGORITHM_ID,
  SECRET_KEY_BYTES,
  PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES,
} from '../sig/ml-dsa.js';
import {
  InvalidInputError,
  SignatureVerificationError,
} from '../errors.js';

const SHARD_VALUE_BYTES = 32;
const SHARD_MAC_BYTES = 32;
const SERIALIZED_SHARD_BYTES = 1 + SHARD_VALUE_BYTES + SHARD_MAC_BYTES; // 65

/**
 * Serialize a shard into a fixed 65-byte format.
 * Format: [index: 1 byte][value: 32 bytes][mac: 32 bytes]
 */
function serializeShard(shard: Shard): Uint8Array {
  const buf = new Uint8Array(SERIALIZED_SHARD_BYTES);
  buf[0] = shard.index;
  buf.set(shard.value, 1);
  buf.set(shard.mac, 1 + SHARD_VALUE_BYTES);
  return buf;
}

/**
 * Deserialize a 65-byte buffer back into a Shard.
 */
function deserializeShard(buf: Uint8Array): Shard {
  return {
    index: buf[0]!,
    value: buf.slice(1, 1 + SHARD_VALUE_BYTES),
    mac: buf.slice(1 + SHARD_VALUE_BYTES, SERIALIZED_SHARD_BYTES),
  };
}

/**
 * Encrypt and sign a shard for distribution to a custodian.
 *
 * Signs the shard with the owner's ML-DSA-65 key (origin proof),
 * then encrypts under the custodian's HPKE public key (confidentiality).
 */
export async function distributeShard(
  shard: Shard,
  custodianPublicKey: Uint8Array,
  ownerSigningKey: Uint8Array,
  options?: { kem?: Kem; info?: Uint8Array },
): Promise<EncryptedShard> {
  // Validate shard
  if (shard.value.length !== SHARD_VALUE_BYTES) {
    throw new InvalidInputError(
      `shard value must be ${String(SHARD_VALUE_BYTES)} bytes, got ${String(shard.value.length)}`,
    );
  }
  if (shard.mac.length !== SHARD_MAC_BYTES) {
    throw new InvalidInputError(
      `shard mac must be ${String(SHARD_MAC_BYTES)} bytes, got ${String(shard.mac.length)}`,
    );
  }

  // Validate signing key
  if (ownerSigningKey.length !== SECRET_KEY_BYTES) {
    throw new InvalidInputError(
      `ownerSigningKey must be ${String(SECRET_KEY_BYTES)} bytes, got ${String(ownerSigningKey.length)}`,
    );
  }

  const kem = options?.kem ?? HYBRID_X25519_MLKEM768;
  const info = options?.info ?? new Uint8Array(0);

  // Validate custodian public key size
  if (custodianPublicKey.length !== kem.publicKeySize) {
    throw new InvalidInputError(
      `custodianPublicKey must be ${String(kem.publicKeySize)} bytes for ${kem.id}, got ${String(custodianPublicKey.length)}`,
    );
  }

  // Step 1: Serialize the shard
  const serialized = serializeShard(shard);

  // Step 2: Sign with owner's ML-DSA-65 key
  const signature = sign(serialized, ownerSigningKey);

  // Step 3: Build plaintext = serialized shard || signature
  const plaintext = new Uint8Array(SERIALIZED_SHARD_BYTES + SIGNATURE_BYTES);
  plaintext.set(serialized, 0);
  plaintext.set(signature, SERIALIZED_SHARD_BYTES);

  // Step 4: Encrypt under custodian's HPKE public key
  const sealed = await sealBase(kem, custodianPublicKey, info, new Uint8Array(0), plaintext);

  return {
    enc: sealed.enc,
    ciphertext: sealed.ciphertext,
    iv: sealed.iv,
    tag: sealed.tag,
    kemId: kem.id,
    sigAlgorithmId: ALGORITHM_ID,
  };
}

/**
 * Decrypt and verify a shard received from storage/transport.
 *
 * Decrypts with the custodian's HPKE private key, then verifies
 * the owner's ML-DSA-65 signature to confirm origin.
 */
export async function recoverShard(
  encryptedShard: EncryptedShard,
  custodianPrivateKey: Uint8Array,
  ownerVerifyKey: Uint8Array,
  options?: { kem?: Kem; info?: Uint8Array },
): Promise<Shard> {
  const kem = options?.kem ?? HYBRID_X25519_MLKEM768;
  const info = options?.info ?? new Uint8Array(0);

  // Validate KEM ID
  if (encryptedShard.kemId !== kem.id) {
    throw new InvalidInputError(
      `KEM mismatch: encrypted shard uses "${encryptedShard.kemId}" but recover was called with "${kem.id}"`,
    );
  }

  // Validate owner verify key
  if (ownerVerifyKey.length !== PUBLIC_KEY_BYTES) {
    throw new InvalidInputError(
      `ownerVerifyKey must be ${String(PUBLIC_KEY_BYTES)} bytes, got ${String(ownerVerifyKey.length)}`,
    );
  }

  // Step 1: Decrypt with custodian's HPKE private key
  // openBase throws AuthenticationError on failure
  const plaintext = await openBase(kem, encryptedShard.enc, custodianPrivateKey, info, new Uint8Array(0), {
    ciphertext: encryptedShard.ciphertext,
    iv: encryptedShard.iv,
    tag: encryptedShard.tag,
  });

  // Step 2: Split plaintext into serialized shard + signature
  const serialized = plaintext.slice(0, SERIALIZED_SHARD_BYTES);
  const signature = plaintext.slice(SERIALIZED_SHARD_BYTES);

  // Step 3: Verify ML-DSA-65 signature
  if (!verify(signature, serialized, ownerVerifyKey)) {
    throw new SignatureVerificationError(
      'ML-DSA-65 signature verification failed: shard origin could not be authenticated',
    );
  }

  // Step 4: Deserialize shard
  return deserializeShard(serialized);
}
