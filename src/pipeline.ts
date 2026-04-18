/**
 * Preservation pipeline — single preserve()/recover() API chaining
 * AES-256-GCM, Shamir splitting, and shard encryption (HPKE + ML-DSA-65).
 *
 * References:
 * - PreVeil (2024) — DEK → Shamir → encrypted shares pattern
 * - Crypt4GH (GA4GH) — fresh DEK per file, no key reuse
 * - NIST SP 800-56C — single-purpose derived keys
 */

import type { Kem } from './kem/kem.js';
import type { PreservationPackage, EncryptedShard } from './types.js';
import { HYBRID_X25519_MLKEM768 } from './kem/hybrid-kem.js';
import { _importRawKey } from './keys.js';
import { encryptChunk, decryptChunk } from './aes-gcm.js';
import { splitKey, combineShards } from './sss/key-split.js';
import { distributeShard, recoverShard } from './sss/shard-encrypt.js';
import { SECRET_KEY_BYTES } from './sig/ml-dsa.js';
import { InvalidInputError } from './errors.js';
import { randomBytes } from './internal/random.js';

const DEK_BYTES = 32;
const DEFAULT_THRESHOLD = 3;
const PIPELINE_VERSION = '0.5.0';

/**
 * Preserve data by encrypting it and distributing the key among custodians.
 *
 * Flow: generate DEK → AES encrypt → Shamir split DEK → sign+encrypt each shard.
 * The DEK never appears in the output — it is fully decomposed into shards.
 */
export async function preserve(
  data: Uint8Array,
  custodianPublicKeys: Uint8Array[],
  ownerSigningKey: Uint8Array,
  options?: { threshold?: number; kem?: Kem },
): Promise<PreservationPackage> {
  const threshold = options?.threshold ?? DEFAULT_THRESHOLD;
  const kem = options?.kem ?? HYBRID_X25519_MLKEM768;

  // Validate inputs
  if (data.length === 0) {
    throw new InvalidInputError('data must be non-empty');
  }
  if (custodianPublicKeys.length < threshold) {
    throw new InvalidInputError(
      `need at least ${String(threshold)} custodian public keys, got ${String(custodianPublicKeys.length)}`,
    );
  }
  if (ownerSigningKey.length !== SECRET_KEY_BYTES) {
    throw new InvalidInputError(
      `ownerSigningKey must be ${String(SECRET_KEY_BYTES)} bytes, got ${String(ownerSigningKey.length)}`,
    );
  }

  // Step 1: Generate random DEK and encrypt data
  const rawDek = randomBytes(DEK_BYTES);
  const keyHandle = await _importRawKey(rawDek);
  const encryptedData = await encryptChunk(keyHandle, data, new Uint8Array(0));

  // Step 2: Split DEK via Shamir
  const splitResult = await splitKey(rawDek, {
    threshold,
    shares: custodianPublicKeys.length,
  });

  // Step 3: Sign + encrypt each shard for its custodian
  const encryptedShards: EncryptedShard[] = [];
  for (let i = 0; i < splitResult.shards.length; i++) {
    const encrypted = await distributeShard(
      splitResult.shards[i]!,
      custodianPublicKeys[i]!,
      ownerSigningKey,
      { kem },
    );
    encryptedShards.push(encrypted);
  }

  // Step 4: Best-effort erase DEK from memory
  rawDek.fill(0);

  return {
    encryptedData: {
      ciphertext: encryptedData.ciphertext,
      iv: encryptedData.iv,
      tag: encryptedData.tag,
    },
    encryptedShards,
    metadata: {
      version: PIPELINE_VERSION,
      threshold,
      totalShards: custodianPublicKeys.length,
      kemId: kem.id,
      sigAlgorithmId: 'ML-DSA-65',
    },
  };
}

/**
 * Recover preserved data using custodian private keys.
 *
 * Flow: decrypt+verify shards → Shamir combine → AES decrypt.
 */
export async function recover(
  pkg: PreservationPackage,
  custodianPrivateKeys: { index: number; privateKey: Uint8Array }[],
  ownerVerifyKey: Uint8Array,
  options?: { kem?: Kem },
): Promise<Uint8Array> {
  const kem = options?.kem ?? HYBRID_X25519_MLKEM768;
  const threshold = pkg.metadata.threshold;

  // Validate inputs
  if (custodianPrivateKeys.length < threshold) {
    throw new InvalidInputError(
      `need at least ${String(threshold)} custodian private keys, got ${String(custodianPrivateKeys.length)}`,
    );
  }

  // Step 1: Decrypt and verify each shard
  const shards = [];
  for (const { index, privateKey } of custodianPrivateKeys) {
    const encryptedShard = pkg.encryptedShards[index];
    if (!encryptedShard) {
      throw new InvalidInputError(
        `no encrypted shard at index ${String(index)}`,
      );
    }
    const shard = await recoverShard(encryptedShard, privateKey, ownerVerifyKey, { kem });
    shards.push(shard);
  }

  // Step 2: Reconstruct DEK from shards
  const rawDek = await combineShards(shards);

  // Step 3: Decrypt data
  const keyHandle = await _importRawKey(rawDek);
  const plaintext = await decryptChunk(keyHandle, {
    ciphertext: pkg.encryptedData.ciphertext,
    iv: pkg.encryptedData.iv,
    tag: pkg.encryptedData.tag,
  }, new Uint8Array(0));

  // Step 4: Best-effort erase DEK from memory
  rawDek.fill(0);

  return plaintext;
}
