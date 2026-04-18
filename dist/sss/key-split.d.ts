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
import type { Shard, SplitOptions, SplitResult } from '../types.js';
/**
 * Split a 32-byte secret into Shamir shards with HMAC authentication.
 * Async for forward compatibility with future shard encryption (HPKE).
 */
export declare function splitKey(secret: Uint8Array, options: SplitOptions): Promise<SplitResult>;
/**
 * Reconstruct a secret from Shamir shards and verify HMAC tags.
 * Async for forward compatibility with future shard encryption (HPKE).
 */
export declare function combineShards(shards: readonly Shard[]): Promise<Uint8Array>;
//# sourceMappingURL=key-split.d.ts.map