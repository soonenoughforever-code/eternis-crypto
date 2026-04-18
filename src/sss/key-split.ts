/**
 * Public API for Shamir key splitting with HMAC shard authentication.
 *
 * splitKey() — split a 32-byte secret into HMAC-tagged shards.
 * combineShards() — reconstruct the secret and verify HMAC tags.
 *
 * References:
 * - Shamir (1979) "How to Share a Secret"
 * - PreVeil (2024) Security Whitepaper — plain Shamir + authenticated shards
 */

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { Shard, SplitOptions, SplitResult } from '../types.js';
import { InvalidInputError, ShardAuthenticationError } from '../errors.js';
import { generateShares, reconstructSecret } from './shamir.js';

const SECRET_BYTES = 32;
const MAC_BYTES = 32;
const MAX_SHARES = 255;
const HMAC_DOMAIN = new TextEncoder().encode('eternis-shard-auth-v1');

/**
 * Derive an HMAC key from the secret for shard tagging.
 * hmacKey = HMAC-SHA256(key=secret, data="eternis-shard-auth-v1")
 */
function deriveHmacKey(secret: Uint8Array): Uint8Array {
  return hmac(sha256, secret, HMAC_DOMAIN);
}

/**
 * Compute the HMAC tag for a shard.
 * mac = HMAC-SHA256(key=hmacKey, data=index_byte || shard_value)
 */
function tagShard(hmacKey: Uint8Array, index: number, value: Uint8Array): Uint8Array {
  const data = new Uint8Array(1 + value.length);
  data[0] = index;
  data.set(value, 1);
  return hmac(sha256, hmacKey, data);
}

/**
 * Constant-time byte comparison to prevent timing side-channels.
 * The length check is an early return but is not reachable in normal
 * operation — callers validate that both inputs are MAC_BYTES (32) long
 * before calling this function.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

/**
 * Split a 32-byte secret into Shamir shards with HMAC authentication.
 * Async for forward compatibility with future shard encryption (HPKE).
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function splitKey(
  secret: Uint8Array,
  options: SplitOptions,
): Promise<SplitResult> {
  // Validate inputs
  if (secret.length !== SECRET_BYTES) {
    throw new InvalidInputError(
      `secret must be exactly ${String(SECRET_BYTES)} bytes, got ${String(secret.length)}`,
    );
  }
  if (secret.every((b) => b === 0)) {
    throw new InvalidInputError('secret must not be all zeros');
  }
  if (!Number.isInteger(options.threshold) || options.threshold < 2) {
    throw new InvalidInputError(
      `threshold must be an integer >= 2, got ${String(options.threshold)}`,
    );
  }
  if (!Number.isInteger(options.shares) || options.shares < options.threshold) {
    throw new InvalidInputError(
      `shares must be an integer >= threshold (${String(options.threshold)}), got ${String(options.shares)}`,
    );
  }
  if (options.shares > MAX_SHARES) {
    throw new InvalidInputError(
      `shares must be <= ${String(MAX_SHARES)}, got ${String(options.shares)}`,
    );
  }

  // Generate raw Shamir shares
  const rawShares = generateShares(secret, options.threshold, options.shares);

  // HMAC-tag each shard
  const hmacKey = deriveHmacKey(secret);
  const shards: Shard[] = rawShares.map((raw) => ({
    index: raw.index,
    value: raw.value,
    mac: tagShard(hmacKey, raw.index, raw.value),
  }));

  return { shards, threshold: options.threshold };
}

/**
 * Reconstruct a secret from Shamir shards and verify HMAC tags.
 * Async for forward compatibility with future shard encryption (HPKE).
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function combineShards(
  shards: readonly Shard[],
): Promise<Uint8Array> {
  // Validate inputs
  if (shards.length < 2) {
    throw new InvalidInputError(
      `need at least 2 shards, got ${String(shards.length)}`,
    );
  }

  const indexes = new Set<number>();
  for (const shard of shards) {
    if (indexes.has(shard.index)) {
      throw new InvalidInputError(`duplicate shard index: ${String(shard.index)}`);
    }
    indexes.add(shard.index);

    if (shard.value.length !== SECRET_BYTES) {
      throw new InvalidInputError(
        `shard value must be ${String(SECRET_BYTES)} bytes, got ${String(shard.value.length)} at index ${String(shard.index)}`,
      );
    }
    if (shard.mac.length !== MAC_BYTES) {
      throw new InvalidInputError(
        `shard MAC must be ${String(MAC_BYTES)} bytes, got ${String(shard.mac.length)} at index ${String(shard.index)}`,
      );
    }
  }

  // Reconstruct via Lagrange interpolation
  const rawShares = shards.map((s) => ({ index: s.index, value: s.value }));
  const secret = reconstructSecret(rawShares);

  // Verify HMAC tags
  const hmacKey = deriveHmacKey(secret);
  const failedIndexes: number[] = [];

  for (const shard of shards) {
    const expectedMac = tagShard(hmacKey, shard.index, shard.value);
    if (!constantTimeEqual(expectedMac, shard.mac)) {
      failedIndexes.push(shard.index);
    }
  }

  if (failedIndexes.length > 0) {
    throw new ShardAuthenticationError(
      `HMAC verification failed for shard index(es): ${failedIndexes.join(', ')}`,
    );
  }

  return secret;
}
