# Shamir Key Splitting — Design Spec

## Summary

Add Shamir Secret Sharing (SSS) to `eternis-crypto` as the key-splitting primitive (v0.3.0). Given a 32-byte master key, split it into `n` shards such that any `k` can reconstruct the original — and no `k-1` subset reveals any information about it. Each shard carries an HMAC-SHA256 authentication tag for tamper detection.

**Approach:** Plain Shamir over GF(p) with HMAC-authenticated shards. No Feldman VSS — the dealer is always the user's own client (no adversarial-dealer threat), and Feldman commitments (g^s) are vulnerable to quantum attack via Shor's algorithm. For a 50-year system, information-theoretic security of plain Shamir shares is critical.

**Research basis:**
- Shamir 1979 — foundation construction (polynomial interpolation over GF(p))
- PreVeil 2024 Security Whitepaper — deployed plain Shamir + signed/authenticated shards (FIPS 140-2 cert #3804)
- LINCOS / Braun 2017 — long-term cryptographic storage using Shamir (3,4) with proactive resharing
- Fujiwara 2016 — information-theoretically secure distributed storage with Shamir

**Non-goals (future phases):**
- Shard encryption under custodian public keys (application layer, uses HPKE v0.2)
- Proactive resharing (LINCOS-style periodic shard rotation)
- Custodian assignment and distribution (Vault platform layer)

## Architecture

Three internal layers, one public API surface:

```
key-split.ts (public API: splitKey, combineShards)
    ↓ uses
shamir.ts (polynomial creation, evaluation, Lagrange interpolation)
    ↓ uses
field.ts (256-bit prime field arithmetic)
```

All three files live under `src/sss/`. This follows the existing pattern of `src/kem/` for KEM modules.

## File Structure

### New files

| File | Responsibility | Approximate size |
|---|---|---|
| `src/sss/field.ts` | 256-bit prime field arithmetic (add, sub, mul, inv, pow, byte conversion) | ~80 lines |
| `src/sss/shamir.ts` | Polynomial generation, evaluation, Lagrange interpolation | ~80 lines |
| `src/sss/key-split.ts` | Public API: splitKey, combineShards, validation, HMAC tagging | ~100 lines |
| `test/field.test.ts` | Field arithmetic correctness, edge cases, boundary values | ~80 lines |
| `test/shamir.test.ts` | Polynomial evaluation, reconstruction, known vectors | ~80 lines |
| `test/key-split.test.ts` | Round-trip, tamper detection, validation, error paths | ~100 lines |

### Modified files

| File | Change |
|---|---|
| `src/index.ts` | Add v0.3 exports: splitKey, combineShards, Shard, SplitOptions, SplitResult, ShardAuthenticationError |
| `src/errors.ts` | Add ShardAuthenticationError class |
| `src/types.ts` | Add Shard, SplitOptions, SplitResult interfaces |
| `test/public-api.test.ts` | Add v0.3 export assertions |
| `package.json` | Bump version to 0.3.0 |

## Prime Field — GF(p)

**Prime:** `p = 2^256 - 189`

This is the largest 256-bit prime below 2^256. Almost every 32-byte value (0 to 2^256 - 1) is strictly less than `p`. The 189 values in [p, 2^256 - 1] have negligible probability (~2^-248) for a random AES key, but the implementation always reduces the secret mod p on input to handle this correctly. On output, `bigIntToBytes` zero-pads to 32 bytes, so the round-trip is exact for any value < p.

**Operations (all results in [0, p)):**

| Function | Signature | Description |
|---|---|---|
| `mod(a)` | `(a: bigint) => bigint` | Reduce into [0, p). Handles negative inputs. |
| `add(a, b)` | `(a: bigint, b: bigint) => bigint` | `(a + b) mod p` |
| `sub(a, b)` | `(a: bigint, b: bigint) => bigint` | `(a - b + p) mod p` — never negative |
| `mul(a, b)` | `(a: bigint, b: bigint) => bigint` | `(a * b) mod p` |
| `inv(a)` | `(a: bigint) => bigint` | `a^(p-2) mod p` via Fermat's little theorem. Throws if `a === 0`. |
| `pow(base, exp)` | `(base: bigint, exp: bigint) => bigint` | Square-and-multiply modular exponentiation |

**Conversion helpers:**

| Function | Signature | Description |
|---|---|---|
| `bytesToBigInt(b)` | `(b: Uint8Array) => bigint` | 32-byte big-endian → BigInt |
| `bigIntToBytes(n)` | `(n: bigint) => Uint8Array` | BigInt → 32-byte big-endian, zero-padded |

**The prime constant and all field operations are exported only from `src/sss/field.ts` — they are internal to the `sss/` module and not re-exported from `src/index.ts`.**

## Shamir Polynomial Operations

### Split — `generateShares(secret, threshold, totalShares)`

1. Convert the 32-byte `secret` to a BigInt `s` in GF(p).
2. Generate `threshold - 1` random coefficients `a1, ..., a(k-1)` using `crypto.getRandomValues(new Uint8Array(32))` for each, converted to BigInt and reduced mod p.
3. Define polynomial `q(x) = s + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)` over GF(p).
4. For `i = 1` to `totalShares`, compute `y_i = q(i) mod p`.
5. Return shares as `(index: i, value: bigIntToBytes(y_i))` pairs.

**The polynomial coefficients are never stored or returned. They exist only during the split operation and are garbage-collected.**

### Combine — `reconstructSecret(shares)`

1. Accept `k` or more shares, each an `(index, value)` pair.
2. Convert each `value` to BigInt.
3. Apply Lagrange interpolation at `x = 0` over GF(p):

```
secret = Σ_i (y_i * Π_{j≠i} (0 - x_j) / (x_i - x_j)) mod p
```

4. Convert result to 32-byte big-endian.

**Lagrange interpolation is computed using the barycentric form to avoid redundant divisions.** Each `x_i` and `x_j` are small integers (1–255), so the field divisions are cheap.

### Internal exports

`shamir.ts` exports `generateShares` and `reconstructSecret` — used by `key-split.ts` and by tests. Not re-exported from `src/index.ts`.

## HMAC Shard Authentication

### Tagging (during split)

1. Derive an HMAC key from the secret: `hmacKey = HMAC-SHA256(key=secret, data="eternis-shard-auth-v1")`
2. For each shard, compute: `mac = HMAC-SHA256(key=hmacKey, data=index_byte || shard_value)`
   - `index_byte` is the shard index as a single byte (1–255)
   - `shard_value` is the 32-byte shard value
   - Input to HMAC is the 33-byte concatenation

### Verification (during combine)

1. Reconstruct the secret via Lagrange interpolation.
2. Re-derive `hmacKey` from the reconstructed secret (same derivation as above).
3. For each provided shard, recompute the expected MAC and compare in constant time.
4. If any MAC fails: throw `ShardAuthenticationError` with the failing shard index(es).

**Why post-reconstruction verification?** The HMAC key is derived from the secret itself. You can't verify shards until you have the secret. This is by design — it means the MAC tags reveal nothing about the secret to someone who doesn't already have it. PreVeil uses the same approach.

**Constant-time comparison:** MAC verification uses `crypto.subtle.verify` or a constant-time byte comparison to prevent timing side-channels.

### HMAC implementation

Uses `@noble/hashes/hmac` and `@noble/hashes/sha256` — both already available as transitive dependencies of `@noble/hashes` which is in our `package.json`.

## Public API

### Types

```typescript
/** A single shard from a Shamir key split. */
export interface Shard {
  /** Point index on the polynomial (1–255). */
  readonly index: number;
  /** 32-byte shard value (the y-coordinate in GF(p)). */
  readonly value: Uint8Array;
  /** 32-byte HMAC-SHA256 authentication tag. */
  readonly mac: Uint8Array;
}

/** Configuration for splitKey. */
export interface SplitOptions {
  /** Minimum shards needed to reconstruct. Must be >= 2. */
  readonly threshold: number;
  /** Total shards to generate. Must be >= threshold and <= 255. */
  readonly shares: number;
}

/** Result of splitKey. */
export interface SplitResult {
  /** The generated shards, one per share. */
  readonly shards: readonly Shard[];
  /** The threshold that was used (needed for reconstruction metadata). */
  readonly threshold: number;
}
```

### Functions

```typescript
/**
 * Split a 32-byte secret into Shamir shards with HMAC authentication.
 *
 * @param secret - Exactly 32 bytes (e.g., an AES-256 master key).
 * @param options - Threshold and total share count.
 * @returns SplitResult containing the tagged shards.
 * @throws InvalidInputError if inputs fail validation.
 */
export async function splitKey(
  secret: Uint8Array,
  options: SplitOptions,
): Promise<SplitResult>

/**
 * Reconstruct a secret from Shamir shards and verify HMAC tags.
 *
 * @param shards - At least `threshold` shards from the original split.
 * @returns The original 32-byte secret.
 * @throws InvalidInputError if fewer than 2 shards or invalid shard format.
 * @throws ShardAuthenticationError if any shard's HMAC tag is invalid.
 */
export async function combineShards(
  shards: readonly Shard[],
): Promise<Uint8Array>
```

### Validation rules

| Parameter | Rule | Error |
|---|---|---|
| `secret` | Must be exactly 32 bytes | `InvalidInputError` |
| `secret` | Must not be all zeros | `InvalidInputError` |
| `options.threshold` | Must be integer >= 2 | `InvalidInputError` |
| `options.shares` | Must be integer >= threshold | `InvalidInputError` |
| `options.shares` | Must be <= 255 | `InvalidInputError` |
| `shards` (combine) | Must have length >= 2 | `InvalidInputError` |
| `shards` (combine) | All indexes must be unique | `InvalidInputError` |
| `shards` (combine) | All values must be 32 bytes | `InvalidInputError` |
| `shards` (combine) | All MACs must be 32 bytes | `InvalidInputError` |

### Error classes

```typescript
/** Thrown when shard HMAC verification fails during reconstruction. */
export class ShardAuthenticationError extends EternisCryptoError {}
```

## Exports from `src/index.ts`

```typescript
// v0.3 — Shamir key splitting
export type { Shard, SplitOptions, SplitResult } from './types.js';
export { splitKey, combineShards } from './sss/key-split.js';
export { ShardAuthenticationError } from './errors.js';
```

## Testing Strategy

### field.test.ts (~10 tests)

- Field identity: `add(a, 0) === a`, `mul(a, 1) === a`
- Inverse: `mul(a, inv(a)) === 1` for random values
- Boundary: operations with 0, 1, p-1
- Byte conversion round-trip: `bigIntToBytes(bytesToBigInt(b)) === b`
- Zero inverse throws
- Negative handling in `sub` (no underflow)

### shamir.test.ts (~10 tests)

- Known vector: hand-computed (2,3) split with small numbers, verify reconstruction
- Round-trip: random secret → split → combine with exact threshold → matches
- Round-trip: combine with more than threshold shards → matches
- Any k-subset works: split (3,5), try all C(5,3)=10 combinations
- Wrong number of shards (k-1): reconstruction produces wrong value (information-theoretic guarantee)
- Distinct indexes: all share indexes are unique and in [1, n]

### key-split.test.ts (~15 tests)

- Round-trip with default (3,5): split → combine → matches original
- Round-trip with various (k,n): (2,3), (4,7), (5,5)
- Tamper detection: modify one shard value → ShardAuthenticationError
- Tamper detection: modify one shard MAC → ShardAuthenticationError
- Tamper detection: swap two shards' MACs → ShardAuthenticationError
- Tamper detection: modify shard index → ShardAuthenticationError
- Validation: secret not 32 bytes → InvalidInputError
- Validation: all-zero secret → InvalidInputError
- Validation: threshold < 2 → InvalidInputError
- Validation: shares < threshold → InvalidInputError
- Validation: shares > 255 → InvalidInputError
- Validation: duplicate shard indexes in combine → InvalidInputError
- Validation: fewer than 2 shards in combine → InvalidInputError
- Shard format: each shard has index (number), value (32 bytes), mac (32 bytes)
- Determinism: same secret with different splits produces different shards (random coefficients)

### public-api.test.ts (update existing)

- Add assertions for v0.3 exports: `splitKey`, `combineShards`, `Shard`, `SplitOptions`, `SplitResult`, `ShardAuthenticationError`

## Security Properties

| Property | Guarantee | Basis |
|---|---|---|
| Information-theoretic secrecy | k-1 shards reveal zero information about the secret | Shamir 1979 Theorem 1 — every candidate secret is equally likely given k-1 shares |
| Quantum resistance | Shares are unconditionally secure — no quantum algorithm helps | No computational assumption; purely combinatorial |
| Tamper detection | Modified shards detected via HMAC-SHA256 | HMAC security under SHA-256; constant-time comparison prevents timing attacks |
| No coefficient leakage | Random polynomial coefficients exist only during split, then GC'd | Implementation discipline — no persistence of intermediate values |
| CSPRNG shard generation | Polynomial coefficients from `crypto.getRandomValues()` | Web Crypto API, backed by OS entropy source |

## Dependencies

**No new dependencies.** All functionality is implemented using:
- Native `BigInt` (Node.js 22+)
- `crypto.getRandomValues()` (Web Crypto API)
- `@noble/hashes/hmac` + `@noble/hashes/sha256` (already in `package.json` as `@noble/hashes`)

## Version

Bump `package.json` version from `0.2.0` to `0.3.0`.
