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
import type { PreservationPackage, EncryptedShard, Shard } from './types.js';
import { HYBRID_X25519_MLKEM768 } from './kem/hybrid-kem.js';
import { _importRawKey } from './keys.js';
import { encryptChunk, decryptChunk } from './aes-gcm.js';
import { splitKey, combineShards } from './sss/key-split.js';
import { distributeShard, recoverShard } from './sss/shard-encrypt.js';
import { SECRET_KEY_BYTES } from './sig/ml-dsa.js';
import { InvalidInputError } from './errors.js';
import { randomBytes } from './internal/random.js';
import { P, bytesToBigInt } from './sss/field.js';

const DEK_BYTES = 32;
const DEFAULT_THRESHOLD = 3;
const PIPELINE_VERSION = '0.6.0';
const PACKAGE_ID_BYTES = 16;
const SIG_ALGORITHM_ID = 'ML-DSA-65';

type PreservationMetadata = PreservationPackage['metadata'];

const UNIT_SEP = new Uint8Array([0x1f]);

/** Lowercase-hex encode (used only for the public package id). */
function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/**
 * Deterministically encode a labeled, unit-separated field list into bytes.
 * The 0x1f separators make the encoding unambiguous (so ("1","23") and
 * ("12","3") never collide), which matters because these bytes are used as
 * authenticated context (HPKE info / AEAD AAD).
 */
function encodeContext(label: string, parts: (string | number)[]): Uint8Array {
  const enc = new TextEncoder();
  const chunks: Uint8Array[] = [enc.encode(label)];
  for (const p of parts) {
    chunks.push(UNIT_SEP, enc.encode(String(p)));
  }
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/**
 * F8: authenticated context bound into the data ciphertext's AAD. Any edit to
 * a metadata field changes this AAD, so recover()'s AES-GCM decrypt fails
 * instead of silently trusting attacker-supplied metadata.
 */
function dataAAD(m: PreservationMetadata): Uint8Array {
  return encodeContext('eternis-preservation-aad-v1', [
    m.version,
    m.threshold,
    m.totalShards,
    m.kemId,
    m.sigAlgorithmId,
    m.packageId,
  ]);
}

/**
 * F6: authenticated context bound into each shard's HPKE `info`. Binds a shard
 * to its package and its slot (plus the algorithm ids), so a validly signed
 * shard cannot be replayed/substituted across packages or slots; such a shard
 * fails HPKE decryption early rather than being caught late by the HMAC.
 */
function shardInfo(m: PreservationMetadata, slot: number): Uint8Array {
  return encodeContext('eternis-shard-info-v1', [
    m.packageId,
    slot,
    m.threshold,
    m.totalShards,
    m.kemId,
    m.sigAlgorithmId,
  ]);
}

/**
 * Draw a random 32-byte DEK whose big-endian value lies in the Shamir field
 * [0, P), P = 2^256 - 189. Rejection-samples the ~189/2^256 out-of-field draws
 * so preserve() can never emit a DEK that splitKey would reduce mod P (F3).
 * The `draw` parameter is injectable for testing; production uses the CSPRNG.
 */
export function _drawInFieldSecret(
  draw: (n: number) => Uint8Array = randomBytes,
): Uint8Array {
  let secret = draw(DEK_BYTES);
  while (bytesToBigInt(secret) >= P) {
    secret = draw(DEK_BYTES);
  }
  return secret;
}

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

  // Step 1: Build the (authenticated) package metadata up front. The data AAD
  // and every shard's HPKE info are derived from it, so it must be fixed before
  // any encryption happens.
  const metadata: PreservationMetadata = {
    version: PIPELINE_VERSION,
    threshold,
    totalShards: custodianPublicKeys.length,
    kemId: kem.id,
    sigAlgorithmId: SIG_ALGORITHM_ID,
    packageId: toHex(randomBytes(PACKAGE_ID_BYTES)),
  };

  // Step 2: Generate random DEK (rejection-sampled into the Shamir field) and
  // encrypt data, binding the metadata into the AAD (F8).
  const rawDek = _drawInFieldSecret();
  const keyHandle = await _importRawKey(rawDek);
  const encryptedData = await encryptChunk(keyHandle, data, dataAAD(metadata));

  // Step 3: Split DEK via Shamir
  const splitResult = await splitKey(rawDek, {
    threshold,
    shares: custodianPublicKeys.length,
  });

  // Step 4: Sign + encrypt each shard for its custodian, binding it to this
  // package and slot via HPKE info (F6).
  const encryptedShards: EncryptedShard[] = [];
  for (let i = 0; i < splitResult.shards.length; i++) {
    const encrypted = await distributeShard(
      splitResult.shards[i]!,
      custodianPublicKeys[i]!,
      ownerSigningKey,
      { kem, info: shardInfo(metadata, i) },
    );
    encryptedShards.push(encrypted);
  }

  // Step 5: Best-effort erase DEK from memory
  rawDek.fill(0);

  return {
    encryptedData: {
      ciphertext: encryptedData.ciphertext,
      iv: encryptedData.iv,
      tag: encryptedData.tag,
    },
    encryptedShards,
    metadata,
  };
}

/**
 * Recover preserved data using custodian private keys.
 *
 * Flow: decrypt+verify shards → Shamir combine → AES decrypt.
 *
 * @param custodianPrivateKeys - One entry per custodian participating in
 *   recovery. `index` is the **0-based slot** of that custodian's shard in
 *   `pkg.encryptedShards` (i.e. their position in the `custodianPublicKeys`
 *   array passed to preserve()), NOT the 1-based Shamir point index. Each
 *   `privateKey` must be the private key of the custodian at that slot.
 */
/**
 * Decrypt and verify a single preserved shard by its slot, rebuilding the same
 * per-slot HPKE info that preserve() bound (F6). Building block for recovery
 * that is performed across more than one location (e.g. server + client).
 */
export async function recoverShardAt(
  pkg: PreservationPackage,
  slotIndex: number,
  custodianPrivateKey: Uint8Array,
  ownerVerifyKey: Uint8Array,
  options?: { kem?: Kem },
): Promise<Shard> {
  const kem = options?.kem ?? HYBRID_X25519_MLKEM768;
  const encryptedShard = pkg.encryptedShards[slotIndex];
  if (!encryptedShard) {
    throw new InvalidInputError(`no encrypted shard at slot ${String(slotIndex)}`);
  }
  return recoverShard(encryptedShard, custodianPrivateKey, ownerVerifyKey, {
    kem,
    info: shardInfo(pkg.metadata, slotIndex),
  });
}

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

  // Step 1: Decrypt and verify each shard, rebuilding the same per-slot HPKE
  // info that preserve() bound (F6). A shard moved to the wrong slot or from a
  // different package fails HPKE decryption here.
  const shards = [];
  for (const { index, privateKey } of custodianPrivateKeys) {
    const encryptedShard = pkg.encryptedShards[index];
    if (!encryptedShard) {
      throw new InvalidInputError(
        `no encrypted shard at slot ${String(index)}`,
      );
    }
    const shard = await recoverShard(encryptedShard, privateKey, ownerVerifyKey, {
      kem,
      info: shardInfo(pkg.metadata, index),
    });
    shards.push(shard);
  }

  // Step 2: Reconstruct DEK from shards
  const rawDek = await combineShards(shards);

  // Step 3: Decrypt data, verifying the metadata AAD binding (F8). Any tamper
  // with the metadata block makes this AES-GCM decrypt fail.
  const keyHandle = await _importRawKey(rawDek);
  const plaintext = await decryptChunk(keyHandle, {
    ciphertext: pkg.encryptedData.ciphertext,
    iv: pkg.encryptedData.iv,
    tag: pkg.encryptedData.tag,
  }, dataAAD(pkg.metadata));

  // Step 4: Best-effort erase DEK from memory
  rawDek.fill(0);

  return plaintext;
}
