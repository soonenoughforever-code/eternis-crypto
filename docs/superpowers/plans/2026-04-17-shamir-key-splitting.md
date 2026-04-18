# Shamir Key Splitting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Shamir Secret Sharing (SSS) key splitting to eternis-crypto (v0.3.0) — split a 32-byte master key into n shards, any k reconstruct it, with HMAC-SHA256 shard authentication.

**Architecture:** Three layers under `src/sss/`: field arithmetic (GF(p), p = 2^256 - 189), Shamir polynomial split/combine via Lagrange interpolation, and a public API with HMAC tagging. Uses native BigInt and existing `@noble/hashes` dependency.

**Tech Stack:** TypeScript, Vitest, native BigInt, `@noble/hashes/hmac` + `@noble/hashes/sha256`, Web Crypto `getRandomValues()`

**Spec:** `docs/superpowers/specs/2026-04-17-shamir-key-splitting-design.md`

---

### Task 0: Types and error class scaffolding

**Files:**
- Modify: `src/types.ts`
- Modify: `src/errors.ts`

- [ ] **Step 1: Add Shard, SplitOptions, SplitResult types to `src/types.ts`**

Append after the existing `MasterKeyPair` interface:

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

- [ ] **Step 2: Add ShardAuthenticationError to `src/errors.ts`**

Append after the existing `KeyWrappingError` class:

```typescript
/** Thrown when shard HMAC verification fails during reconstruction. */
export class ShardAuthenticationError extends EternisCryptoError {}
```

- [ ] **Step 3: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add src/types.ts src/errors.ts
git commit -m "feat: add Shard, SplitOptions, SplitResult types and ShardAuthenticationError"
```

---

### Task 1: Prime field arithmetic

**Files:**
- Create: `src/sss/field.ts`
- Create: `test/field.test.ts`

- [ ] **Step 1: Write the failing tests for field arithmetic**

Create `test/field.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import {
  P,
  mod,
  add,
  sub,
  mul,
  inv,
  pow,
  bytesToBigInt,
  bigIntToBytes,
} from '../src/sss/field.js';

describe('field constants', () => {
  it('P equals 2^256 - 189', () => {
    expect(P).toBe(2n ** 256n - 189n);
  });
});

describe('mod', () => {
  it('reduces positive values into [0, P)', () => {
    expect(mod(0n)).toBe(0n);
    expect(mod(1n)).toBe(1n);
    expect(mod(P)).toBe(0n);
    expect(mod(P + 1n)).toBe(1n);
  });

  it('handles negative values', () => {
    expect(mod(-1n)).toBe(P - 1n);
    expect(mod(-P)).toBe(0n);
  });
});

describe('add', () => {
  it('adds two values mod P', () => {
    expect(add(1n, 2n)).toBe(3n);
  });

  it('wraps on overflow', () => {
    expect(add(P - 1n, 1n)).toBe(0n);
    expect(add(P - 1n, 2n)).toBe(1n);
  });

  it('identity: add(a, 0) === a', () => {
    const a = 123456789n;
    expect(add(a, 0n)).toBe(a);
  });
});

describe('sub', () => {
  it('subtracts two values mod P', () => {
    expect(sub(5n, 3n)).toBe(2n);
  });

  it('wraps on underflow (never negative)', () => {
    expect(sub(0n, 1n)).toBe(P - 1n);
    expect(sub(1n, 3n)).toBe(P - 2n);
  });
});

describe('mul', () => {
  it('multiplies two values mod P', () => {
    expect(mul(3n, 7n)).toBe(21n);
  });

  it('identity: mul(a, 1) === a', () => {
    const a = 999999999n;
    expect(mul(a, 1n)).toBe(a);
  });

  it('zero: mul(a, 0) === 0', () => {
    expect(mul(12345n, 0n)).toBe(0n);
  });
});

describe('inv', () => {
  it('inv(a) * a === 1 mod P', () => {
    const a = 42n;
    expect(mul(a, inv(a))).toBe(1n);
  });

  it('inv(1) === 1', () => {
    expect(inv(1n)).toBe(1n);
  });

  it('inv(P - 1) * (P - 1) === 1 mod P', () => {
    const a = P - 1n;
    expect(mul(a, inv(a))).toBe(1n);
  });

  it('inv of random large value', () => {
    const a = 0xdeadbeefcafebabe1234567890abcdefn;
    expect(mul(a, inv(a))).toBe(1n);
  });

  it('throws on zero', () => {
    expect(() => inv(0n)).toThrow();
  });
});

describe('pow', () => {
  it('computes modular exponentiation', () => {
    expect(pow(2n, 10n)).toBe(1024n);
  });

  it('pow(a, 0) === 1', () => {
    expect(pow(12345n, 0n)).toBe(1n);
  });

  it('pow(a, 1) === a mod P', () => {
    expect(pow(42n, 1n)).toBe(42n);
  });
});

describe('bytesToBigInt / bigIntToBytes', () => {
  it('round-trips a 32-byte value', () => {
    const bytes = new Uint8Array(32);
    bytes[0] = 0xff;
    bytes[31] = 0x01;
    const n = bytesToBigInt(bytes);
    const out = bigIntToBytes(n);
    expect(Array.from(out)).toEqual(Array.from(bytes));
  });

  it('round-trips all zeros', () => {
    const bytes = new Uint8Array(32);
    const n = bytesToBigInt(bytes);
    expect(n).toBe(0n);
    const out = bigIntToBytes(n);
    expect(Array.from(out)).toEqual(Array.from(bytes));
  });

  it('round-trips all 0xff', () => {
    const bytes = new Uint8Array(32).fill(0xff);
    const n = bytesToBigInt(bytes);
    expect(n).toBe(2n ** 256n - 1n);
    const out = bigIntToBytes(n);
    expect(Array.from(out)).toEqual(Array.from(bytes));
  });

  it('bigIntToBytes zero-pads to 32 bytes', () => {
    const out = bigIntToBytes(1n);
    expect(out.length).toBe(32);
    expect(out[31]).toBe(1);
    expect(out[0]).toBe(0);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/field.test.ts`
Expected: FAIL — cannot resolve `../src/sss/field.js`

- [ ] **Step 3: Implement the field module**

Create `src/sss/field.ts`:

```typescript
/**
 * Prime field arithmetic over GF(p) where p = 2^256 - 189.
 * This is the largest 256-bit prime. All operations produce
 * results in [0, p). Used as the substrate for Shamir SSS.
 */

/** The field prime: 2^256 - 189. */
export const P = 2n ** 256n - 189n;

/** Reduce a bigint into [0, P). Handles negative inputs. */
export function mod(a: bigint): bigint {
  const r = a % P;
  return r < 0n ? r + P : r;
}

/** (a + b) mod P */
export function add(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

/** (a - b) mod P — never negative */
export function sub(a: bigint, b: bigint): bigint {
  return mod(a - b);
}

/** (a * b) mod P */
export function mul(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

/**
 * Modular exponentiation via square-and-multiply.
 * Computes base^exp mod P.
 */
export function pow(base: bigint, exp: bigint): bigint {
  base = mod(base);
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) {
      result = mul(result, base);
    }
    base = mul(base, base);
    exp >>= 1n;
  }
  return result;
}

/**
 * Multiplicative inverse via Fermat's little theorem: a^(P-2) mod P.
 * Throws if a === 0 (no inverse exists).
 */
export function inv(a: bigint): bigint {
  a = mod(a);
  if (a === 0n) {
    throw new Error('Cannot compute inverse of zero');
  }
  return pow(a, P - 2n);
}

/** Convert a 32-byte big-endian Uint8Array to a BigInt. */
export function bytesToBigInt(b: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < b.length; i++) {
    result = (result << 8n) | BigInt(b[i]!);
  }
  return result;
}

/** Convert a BigInt to a 32-byte big-endian Uint8Array, zero-padded. */
export function bigIntToBytes(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let val = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/field.test.ts`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/sss/field.ts test/field.test.ts
git commit -m "feat: add GF(2^256-189) prime field arithmetic for Shamir SSS"
```

---

### Task 2: Shamir polynomial split and reconstruct

**Files:**
- Create: `src/sss/shamir.ts`
- Create: `test/shamir.test.ts`

- [ ] **Step 1: Write the failing tests for Shamir split/reconstruct**

Create `test/shamir.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import { generateShares, reconstructSecret } from '../src/sss/shamir.js';
import { P, mod, bytesToBigInt, bigIntToBytes } from '../src/sss/field.js';

describe('generateShares', () => {
  it('returns the correct number of shares', () => {
    const secret = new Uint8Array(32).fill(0x42);
    const shares = generateShares(secret, 3, 5);
    expect(shares.length).toBe(5);
  });

  it('each share has index and 32-byte value', () => {
    const secret = new Uint8Array(32).fill(0xab);
    const shares = generateShares(secret, 2, 3);
    for (const share of shares) {
      expect(share.value.length).toBe(32);
      expect(share.index).toBeGreaterThanOrEqual(1);
      expect(share.index).toBeLessThanOrEqual(3);
    }
  });

  it('all share indexes are unique', () => {
    const secret = new Uint8Array(32).fill(0x01);
    const shares = generateShares(secret, 3, 5);
    const indexes = shares.map((s) => s.index);
    expect(new Set(indexes).size).toBe(5);
  });

  it('different calls produce different shares (random coefficients)', () => {
    const secret = new Uint8Array(32).fill(0x42);
    const shares1 = generateShares(secret, 3, 5);
    const shares2 = generateShares(secret, 3, 5);
    // Extremely unlikely to be identical (random coefficients)
    const allSame = shares1.every(
      (s, i) => Array.from(s.value).join() === Array.from(shares2[i]!.value).join(),
    );
    expect(allSame).toBe(false);
  });
});

describe('reconstructSecret', () => {
  it('reconstructs with exact threshold (3 of 5)', () => {
    const secret = new Uint8Array(32);
    secret[0] = 0xde;
    secret[15] = 0xad;
    secret[31] = 0xef;
    const shares = generateShares(secret, 3, 5);
    const recovered = reconstructSecret(shares.slice(0, 3));
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('reconstructs with more than threshold (5 of 5)', () => {
    const secret = new Uint8Array(32).fill(0xff);
    const shares = generateShares(secret, 3, 5);
    const recovered = reconstructSecret(shares);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('any k-subset of (3,5) works — all 10 combinations', () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const shares = generateShares(secret, 3, 5);
    // Generate all C(5,3) = 10 combinations
    for (let i = 0; i < 5; i++) {
      for (let j = i + 1; j < 5; j++) {
        for (let k = j + 1; k < 5; k++) {
          const subset = [shares[i]!, shares[j]!, shares[k]!];
          const recovered = reconstructSecret(subset);
          expect(Array.from(recovered)).toEqual(Array.from(secret));
        }
      }
    }
  });

  it('reconstructs (2,3) threshold', () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const shares = generateShares(secret, 2, 3);
    const recovered = reconstructSecret([shares[0]!, shares[2]!]);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('reconstructs (5,5) threshold', () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const shares = generateShares(secret, 5, 5);
    const recovered = reconstructSecret(shares);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('k-1 shares produce wrong secret (information-theoretic)', () => {
    const secret = new Uint8Array(32).fill(0x42);
    const shares = generateShares(secret, 3, 5);
    // Only 2 shares (below threshold of 3)
    const wrong = reconstructSecret(shares.slice(0, 2));
    // Should NOT match the original — any value is equally likely
    expect(Array.from(wrong)).not.toEqual(Array.from(secret));
  });
});

describe('known vector — small field manual computation', () => {
  it('reconstructs from a hand-computed (2,3) split', () => {
    // Manual computation over GF(P) with known coefficients:
    // secret s = 42, coefficient a1 = 7
    // q(x) = 42 + 7x mod P
    // q(1) = 49, q(2) = 56, q(3) = 63
    // Lagrange with shares (1,49) and (2,56):
    //   L_1(0) = (0-2)/(1-2) = 2
    //   L_2(0) = (0-1)/(2-1) = -1 mod P = P-1
    //   secret = 49*2 + 56*(P-1) mod P = 98 + 56P - 56 mod P = 42
    const s1 = { index: 1, value: bigIntToBytes(49n) };
    const s2 = { index: 2, value: bigIntToBytes(56n) };
    const recovered = reconstructSecret([s1, s2]);
    expect(bytesToBigInt(recovered)).toBe(42n);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/shamir.test.ts`
Expected: FAIL — cannot resolve `../src/sss/shamir.js`

- [ ] **Step 3: Implement the Shamir module**

Create `src/sss/shamir.ts`:

```typescript
/**
 * Shamir Secret Sharing — polynomial split and Lagrange reconstruction.
 * Operates over GF(p) where p = 2^256 - 189.
 *
 * Reference: Shamir (1979) "How to Share a Secret"
 */

import { mod, add, sub, mul, inv, bytesToBigInt, bigIntToBytes } from './field.js';

/** A raw share: index (x-coordinate) and value (y-coordinate as bytes). */
export interface RawShare {
  readonly index: number;
  readonly value: Uint8Array;
}

/**
 * Evaluate polynomial q(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[k-1]*x^(k-1)
 * at the given point using Horner's method.
 */
function evaluatePolynomial(coeffs: readonly bigint[], x: bigint): bigint {
  let result = 0n;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = add(mul(result, x), coeffs[i]!);
  }
  return result;
}

/**
 * Split a 32-byte secret into shares using a random polynomial of degree (threshold - 1).
 *
 * @param secret - Exactly 32 bytes.
 * @param threshold - Minimum shares for reconstruction (k). Must be >= 2.
 * @param totalShares - Total shares to generate (n). Must be >= threshold, <= 255.
 * @returns Array of RawShare (index + 32-byte value). No HMAC tags — that's key-split.ts's job.
 */
export function generateShares(
  secret: Uint8Array,
  threshold: number,
  totalShares: number,
): RawShare[] {
  const s = bytesToBigInt(secret);

  // Build polynomial: q(x) = s + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
  const coeffs: bigint[] = [mod(s)];
  for (let i = 1; i < threshold; i++) {
    const randBytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(randBytes);
    coeffs.push(mod(bytesToBigInt(randBytes)));
  }

  // Evaluate at x = 1, 2, ..., totalShares
  const shares: RawShare[] = [];
  for (let i = 1; i <= totalShares; i++) {
    const y = evaluatePolynomial(coeffs, BigInt(i));
    shares.push({ index: i, value: bigIntToBytes(y) });
  }

  return shares;
}

/**
 * Reconstruct the secret from shares via Lagrange interpolation at x = 0.
 *
 * @param shares - At least threshold shares with unique indexes.
 * @returns The 32-byte reconstructed secret.
 */
export function reconstructSecret(shares: readonly RawShare[]): Uint8Array {
  const points = shares.map((s) => ({
    x: BigInt(s.index),
    y: bytesToBigInt(s.value),
  }));

  let secret = 0n;

  for (let i = 0; i < points.length; i++) {
    const { x: xi, y: yi } = points[i]!;

    // Compute Lagrange basis polynomial L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
    let numerator = 1n;
    let denominator = 1n;

    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      const xj = points[j]!.x;
      numerator = mul(numerator, sub(0n, xj));      // (0 - x_j)
      denominator = mul(denominator, sub(xi, xj));   // (x_i - x_j)
    }

    const lagrangeCoeff = mul(numerator, inv(denominator));
    secret = add(secret, mul(yi, lagrangeCoeff));
  }

  return bigIntToBytes(secret);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/shamir.test.ts`
Expected: All tests PASS.

- [ ] **Step 5: Run full test suite to check nothing broke**

Run: `npx vitest run`
Expected: All existing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add src/sss/shamir.ts test/shamir.test.ts
git commit -m "feat: add Shamir polynomial split and Lagrange reconstruction"
```

---

### Task 3: HMAC shard authentication and public API

**Files:**
- Create: `src/sss/key-split.ts`
- Create: `test/key-split.test.ts`

- [ ] **Step 1: Write the failing tests for splitKey and combineShards**

Create `test/key-split.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import { splitKey, combineShards } from '../src/sss/key-split.js';
import { InvalidInputError, ShardAuthenticationError } from '../src/errors.js';
import type { Shard } from '../src/types.js';

describe('splitKey + combineShards round-trip', () => {
  it('(3,5) round-trip', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });

    expect(result.shards.length).toBe(5);
    expect(result.threshold).toBe(3);

    const recovered = await combineShards(result.shards.slice(0, 3));
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('(2,3) round-trip', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 2, shares: 3 });
    const recovered = await combineShards([result.shards[0]!, result.shards[2]!]);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('(4,7) round-trip', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 4, shares: 7 });
    const recovered = await combineShards(result.shards.slice(0, 4));
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('(5,5) round-trip', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 5, shares: 5 });
    const recovered = await combineShards(result.shards);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('more than threshold shards also works', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    const recovered = await combineShards(result.shards);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });
});

describe('shard format', () => {
  it('each shard has index, 32-byte value, 32-byte mac', async () => {
    const secret = new Uint8Array(32).fill(0xab);
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    for (const shard of result.shards) {
      expect(typeof shard.index).toBe('number');
      expect(shard.index).toBeGreaterThanOrEqual(1);
      expect(shard.index).toBeLessThanOrEqual(5);
      expect(shard.value.length).toBe(32);
      expect(shard.mac.length).toBe(32);
    }
  });

  it('different splits produce different shards', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    const r1 = await splitKey(secret, { threshold: 3, shares: 5 });
    const r2 = await splitKey(secret, { threshold: 3, shares: 5 });
    const allSame = r1.shards.every(
      (s, i) => Array.from(s.value).join() === Array.from(r2.shards[i]!.value).join(),
    );
    expect(allSame).toBe(false);
  });
});

describe('tamper detection', () => {
  it('modified shard value throws ShardAuthenticationError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    const shards = result.shards.map((s) => ({ ...s }));
    const tampered = new Uint8Array(shards[0]!.value);
    tampered.set([tampered[0]! ^ 0x01], 0);
    shards[0] = { ...shards[0]!, value: tampered };
    await expect(combineShards(shards.slice(0, 3))).rejects.toThrow(ShardAuthenticationError);
  });

  it('modified shard MAC throws ShardAuthenticationError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    const shards = result.shards.map((s) => ({ ...s }));
    const tampered = new Uint8Array(shards[1]!.mac);
    tampered.set([tampered[0]! ^ 0x01], 0);
    shards[1] = { ...shards[1]!, mac: tampered };
    await expect(combineShards(shards.slice(0, 3))).rejects.toThrow(ShardAuthenticationError);
  });

  it('swapped MACs between shards throws ShardAuthenticationError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    const shards = result.shards.map((s) => ({ ...s }));
    // Swap MACs of shard 0 and shard 1
    const mac0 = shards[0]!.mac;
    shards[0] = { ...shards[0]!, mac: shards[1]!.mac };
    shards[1] = { ...shards[1]!, mac: mac0 };
    await expect(combineShards(shards.slice(0, 3))).rejects.toThrow(ShardAuthenticationError);
  });

  it('modified shard index throws ShardAuthenticationError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    // Use shards 0,1,2 but change shard 0's index
    // This will cause wrong reconstruction AND MAC mismatch
    const shards: Shard[] = [
      { index: 99, value: result.shards[0]!.value, mac: result.shards[0]!.mac },
      result.shards[1]!,
      result.shards[2]!,
    ];
    await expect(combineShards(shards)).rejects.toThrow(ShardAuthenticationError);
  });
});

describe('splitKey validation', () => {
  it('secret not 32 bytes throws InvalidInputError', async () => {
    await expect(splitKey(new Uint8Array(16), { threshold: 2, shares: 3 })).rejects.toThrow(
      InvalidInputError,
    );
    await expect(splitKey(new Uint8Array(33), { threshold: 2, shares: 3 })).rejects.toThrow(
      InvalidInputError,
    );
    await expect(splitKey(new Uint8Array(0), { threshold: 2, shares: 3 })).rejects.toThrow(
      InvalidInputError,
    );
  });

  it('all-zero secret throws InvalidInputError', async () => {
    await expect(splitKey(new Uint8Array(32), { threshold: 2, shares: 3 })).rejects.toThrow(
      InvalidInputError,
    );
  });

  it('threshold < 2 throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 1, shares: 3 })).rejects.toThrow(InvalidInputError);
    await expect(splitKey(secret, { threshold: 0, shares: 3 })).rejects.toThrow(InvalidInputError);
  });

  it('shares < threshold throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 3, shares: 2 })).rejects.toThrow(InvalidInputError);
  });

  it('shares > 255 throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 2, shares: 256 })).rejects.toThrow(
      InvalidInputError,
    );
  });

  it('non-integer threshold throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 2.5, shares: 5 })).rejects.toThrow(
      InvalidInputError,
    );
  });

  it('non-integer shares throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 3, shares: 5.5 })).rejects.toThrow(
      InvalidInputError,
    );
  });
});

describe('combineShards validation', () => {
  it('fewer than 2 shards throws InvalidInputError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 2, shares: 3 });
    await expect(combineShards([result.shards[0]!])).rejects.toThrow(InvalidInputError);
    await expect(combineShards([])).rejects.toThrow(InvalidInputError);
  });

  it('duplicate indexes throw InvalidInputError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 2, shares: 3 });
    const dup: Shard[] = [result.shards[0]!, result.shards[0]!];
    await expect(combineShards(dup)).rejects.toThrow(InvalidInputError);
  });

  it('shard value not 32 bytes throws InvalidInputError', async () => {
    const bad: Shard[] = [
      { index: 1, value: new Uint8Array(16), mac: new Uint8Array(32) },
      { index: 2, value: new Uint8Array(32), mac: new Uint8Array(32) },
    ];
    await expect(combineShards(bad)).rejects.toThrow(InvalidInputError);
  });

  it('shard MAC not 32 bytes throws InvalidInputError', async () => {
    const bad: Shard[] = [
      { index: 1, value: new Uint8Array(32), mac: new Uint8Array(16) },
      { index: 2, value: new Uint8Array(32), mac: new Uint8Array(32) },
    ];
    await expect(combineShards(bad)).rejects.toThrow(InvalidInputError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/key-split.test.ts`
Expected: FAIL — cannot resolve `../src/sss/key-split.js`

- [ ] **Step 3: Implement the key-split module**

Create `src/sss/key-split.ts`:

```typescript
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
import { sha256 } from '@noble/hashes/sha256.js';
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
 */
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
 */
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/key-split.test.ts`
Expected: All tests PASS.

**Note on `@noble/hashes` import paths:** Check if the correct import paths are `@noble/hashes/hmac.js` and `@noble/hashes/sha256.js` (with `.js` extension). If they fail, try without the `.js` extension: `@noble/hashes/hmac` and `@noble/hashes/sha256`. The existing codebase uses `@noble/hashes/sha3.js` in `src/kem/hybrid-kem.ts`, so the `.js` extension should work. If not, check `node_modules/@noble/hashes/package.json` for the correct subpath exports.

- [ ] **Step 5: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass (existing + new).

- [ ] **Step 6: Commit**

```bash
git add src/sss/key-split.ts test/key-split.test.ts
git commit -m "feat: add splitKey/combineShards with HMAC shard authentication"
```

---

### Task 4: Public API exports and version bump

**Files:**
- Modify: `src/index.ts`
- Modify: `test/public-api.test.ts`
- Modify: `package.json`

- [ ] **Step 1: Update `src/index.ts` with v0.3 exports**

Add the following block after the v0.2 exports:

```typescript
// v0.3 — Shamir key splitting
export type { Shard, SplitOptions, SplitResult } from './types.js';
export { splitKey, combineShards } from './sss/key-split.js';
export { ShardAuthenticationError } from './errors.js';
```

Also add `ShardAuthenticationError` to the existing errors export block. The final errors section should be:

```typescript
// Shared errors
export {
  EternisCryptoError,
  AuthenticationError,
  KeyExhaustedError,
  InvalidInputError,
  DecapsulationError,
  KeyWrappingError,
  ShardAuthenticationError,
} from './errors.js';
```

Since `ShardAuthenticationError` is now exported in the errors block, the v0.3 section should only export the types and functions:

```typescript
// v0.3 — Shamir key splitting
export type { Shard, SplitOptions, SplitResult } from './types.js';
export { splitKey, combineShards } from './sss/key-split.js';
```

- [ ] **Step 2: Update `test/public-api.test.ts`**

In the `exports exactly the expected symbols` test, add the v0.3 symbols to the expected set:

```typescript
const expected = new Set([
  // v0.1 — AES-256-GCM
  'KeyHandle',
  'generateKey',
  'encryptChunk',
  'decryptChunk',
  // v0.2 — HPKE key wrapping
  'DHKEM_X25519',
  'HYBRID_X25519_MLKEM768',
  'generateMasterKeyPair',
  'wrapKey',
  'unwrapKey',
  // v0.3 — Shamir key splitting
  'splitKey',
  'combineShards',
  // Errors
  'EternisCryptoError',
  'AuthenticationError',
  'KeyExhaustedError',
  'InvalidInputError',
  'DecapsulationError',
  'KeyWrappingError',
  'ShardAuthenticationError',
]);
```

In the `does not expose test-only or internal symbols` test, add the Shamir internals to the forbidden list:

```typescript
const forbidden = [
  '_importKeyForTesting',
  '_encryptChunkWithIV',
  '_internals',
  'InvocationCounter',
  'randomBytes',
  '_dh',
  '_extractAndExpand',
  '_combiner',
  '_keySchedule',
  'sealBase',
  'openBase',
  'extract',
  'expand',
  'labeledExtract',
  'labeledExpand',
  'concat',
  'i2osp',
  // Shamir internals
  'generateShares',
  'reconstructSecret',
  'P',
  'mod',
  'add',
  'sub',
  'mul',
  'inv',
  'pow',
  'bytesToBigInt',
  'bigIntToBytes',
];
```

- [ ] **Step 3: Bump version in `package.json`**

Change `"version": "0.2.0"` to `"version": "0.3.0"`.

- [ ] **Step 4: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass.

- [ ] **Step 5: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 6: Commit**

```bash
git add src/index.ts test/public-api.test.ts package.json
git commit -m "chore: export Shamir key splitting API, bump version to 0.3.0"
```

---

### Task 5: Audit gate — full test suite + review

This is the verification gate before merge. No new code — just validation.

- [ ] **Step 1: Run the complete test suite**

Run: `npx vitest run`
Expected: All tests pass. Count should be approximately 119 (existing) + 10 (field) + 10 (shamir) + 15 (key-split) + 2 (public-api updates) ≈ 155+ tests.

- [ ] **Step 2: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Run linter**

Run: `npx eslint src test --ext .ts`
Expected: No errors (warnings acceptable if consistent with existing code).

- [ ] **Step 4: Verify exports**

Run: `npx vitest run test/public-api.test.ts`
Expected: Both public API tests pass — all v0.1, v0.2, v0.3 exports present, no internals leaked.

- [ ] **Step 5: Manual spot-check**

Verify these properties by reading the code:
1. `src/sss/field.ts` — `P` is `2n ** 256n - 189n`, `inv` throws on zero, `mod` handles negatives
2. `src/sss/shamir.ts` — coefficients use `crypto.getRandomValues`, polynomial evaluated via Horner's method, Lagrange uses field operations
3. `src/sss/key-split.ts` — HMAC domain is `"eternis-shard-auth-v1"`, constant-time comparison used, all validation rules from spec are implemented
4. No internal symbols re-exported from `src/index.ts`
