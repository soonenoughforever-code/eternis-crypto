# Shard Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ML-DSA-65 signing and HPKE shard encryption so shards can be securely distributed to custodians with origin authentication.

**Architecture:** Two new modules — `src/sig/ml-dsa.ts` (ML-DSA-65 wrapper for keygen/sign/verify) and `src/sss/shard-encrypt.ts` (distributeShard/recoverShard composing HPKE + ML-DSA). Sign-then-encrypt pattern: sign the shard with the owner's ML-DSA-65 key, then encrypt under the custodian's HPKE public key.

**Tech Stack:** `@noble/post-quantum/ml-dsa.js` (already in package.json), existing HPKE from `src/hpke.ts`, existing Shamir types from `src/types.ts`.

**Design spec:** `docs/superpowers/specs/2026-04-17-shard-encryption-design.md`

---

## File Structure

### New files

| File | Responsibility |
|---|---|
| `src/sig/ml-dsa.ts` | ML-DSA-65 wrapper: generateSigningKeyPair, sign, verify |
| `src/sss/shard-encrypt.ts` | Public API: distributeShard, recoverShard, shard serialization |
| `test/ml-dsa.test.ts` | ML-DSA-65 keygen, sign/verify, error cases |
| `test/shard-encrypt.test.ts` | Round-trip, tampering, wrong keys, error cases |

### Modified files

| File | Change |
|---|---|
| `src/types.ts` | Add SigningKeyPair, EncryptedShard interfaces |
| `src/errors.ts` | Add SignatureVerificationError class |
| `src/index.ts` | Add v0.4 exports |
| `test/public-api.test.ts` | Add v0.4 export assertions + forbidden internals |
| `package.json` | Bump version to 0.4.0 |

---

### Task 1: Types and Error Class

**Files:**
- Modify: `src/types.ts`
- Modify: `src/errors.ts`
- Test: `test/public-api.test.ts` (later, in Task 6)

- [ ] **Step 1: Add SigningKeyPair and EncryptedShard interfaces to `src/types.ts`**

Open `src/types.ts`. After the `SplitResult` interface (the last interface in the file), add:

```typescript
/** An ML-DSA-65 signing keypair. */
export interface SigningKeyPair {
  /** 1,952-byte ML-DSA-65 public (verification) key. */
  readonly publicKey: Uint8Array;
  /** 4,032-byte ML-DSA-65 secret (signing) key. */
  readonly secretKey: Uint8Array;
  /** Algorithm identifier: "ML-DSA-65". */
  readonly algorithmId: string;
}

/** An encrypted shard for distribution to a custodian. */
export interface EncryptedShard {
  /** HPKE encapsulation (KEM-dependent size). */
  readonly enc: Uint8Array;
  /** AES-256-GCM encrypted (shard + signature). */
  readonly ciphertext: Uint8Array;
  /** 12-byte nonce from HPKE key schedule. */
  readonly iv: Uint8Array;
  /** 16-byte GCM authentication tag. */
  readonly tag: Uint8Array;
  /** Identifies which KEM was used. */
  readonly kemId: string;
  /** Identifies which signature algorithm was used. */
  readonly sigAlgorithmId: string;
}
```

- [ ] **Step 2: Add SignatureVerificationError to `src/errors.ts`**

Open `src/errors.ts`. After the `ShardAuthenticationError` class (the last class in the file), add:

```typescript
/** Thrown when ML-DSA-65 signature verification fails during shard recovery. */
export class SignatureVerificationError extends EternisCryptoError {}
```

- [ ] **Step 3: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors (types are just interfaces, error is just a class).

- [ ] **Step 4: Commit**

```bash
git add src/types.ts src/errors.ts
git commit -m "feat(types): add SigningKeyPair, EncryptedShard, and SignatureVerificationError for v0.4"
```

---

### Task 2: ML-DSA-65 Signing Module

**Files:**
- Create: `src/sig/ml-dsa.ts`
- Test: `test/ml-dsa.test.ts`

**Context:** This module wraps `@noble/post-quantum/ml-dsa.js`. The `@noble/post-quantum` package is already in `package.json` (version ^0.6.1). The API for the underlying library is:
- `ml_dsa65.keygen()` returns `{ publicKey: Uint8Array, secretKey: Uint8Array }`
- `ml_dsa65.sign(message, secretKey)` returns `Uint8Array` (3,309 bytes) — **message first, then secretKey**
- `ml_dsa65.verify(signature, message, publicKey)` returns `boolean` — **signature first, then message, then publicKey**

Key sizes: publicKey = 1,952 bytes, secretKey = 4,032 bytes, signature = 3,309 bytes.

- [ ] **Step 1: Write the failing tests in `test/ml-dsa.test.ts`**

Create `test/ml-dsa.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import {
  generateSigningKeyPair,
  sign,
  verify,
  ALGORITHM_ID,
  PUBLIC_KEY_BYTES,
  SECRET_KEY_BYTES,
  SIGNATURE_BYTES,
} from '../src/sig/ml-dsa.js';
import { InvalidInputError } from '../src/errors.js';

describe('generateSigningKeyPair', () => {
  it('produces correct key sizes', () => {
    const kp = generateSigningKeyPair();
    expect(kp.publicKey.length).toBe(1952);
    expect(kp.secretKey.length).toBe(4032);
  });

  it('sets algorithmId to ML-DSA-65', () => {
    const kp = generateSigningKeyPair();
    expect(kp.algorithmId).toBe('ML-DSA-65');
  });

  it('produces different keypairs each call', () => {
    const kp1 = generateSigningKeyPair();
    const kp2 = generateSigningKeyPair();
    expect(Array.from(kp1.publicKey)).not.toEqual(Array.from(kp2.publicKey));
  });
});

describe('sign + verify round-trip', () => {
  it('signs and verifies a small message', () => {
    const kp = generateSigningKeyPair();
    const msg = new TextEncoder().encode('hello eternis');
    const sig = sign(msg, kp.secretKey);
    expect(sig.length).toBe(3309);
    expect(verify(sig, msg, kp.publicKey)).toBe(true);
  });

  it('signs and verifies an empty message', () => {
    const kp = generateSigningKeyPair();
    const msg = new Uint8Array(0);
    const sig = sign(msg, kp.secretKey);
    expect(verify(sig, msg, kp.publicKey)).toBe(true);
  });

  it('signs and verifies a large message (64 KB)', () => {
    const kp = generateSigningKeyPair();
    const msg = crypto.getRandomValues(new Uint8Array(65536));
    const sig = sign(msg, kp.secretKey);
    expect(verify(sig, msg, kp.publicKey)).toBe(true);
  });
});

describe('verify rejects invalid inputs', () => {
  it('wrong public key returns false', () => {
    const kp1 = generateSigningKeyPair();
    const kp2 = generateSigningKeyPair();
    const msg = new TextEncoder().encode('test');
    const sig = sign(msg, kp1.secretKey);
    expect(verify(sig, msg, kp2.publicKey)).toBe(false);
  });

  it('tampered signature returns false', () => {
    const kp = generateSigningKeyPair();
    const msg = new TextEncoder().encode('test');
    const sig = sign(msg, kp.secretKey);
    const tampered = new Uint8Array(sig);
    tampered[0] ^= 0x01;
    expect(verify(tampered, msg, kp.publicKey)).toBe(false);
  });

  it('tampered message returns false', () => {
    const kp = generateSigningKeyPair();
    const msg = new TextEncoder().encode('test');
    const sig = sign(msg, kp.secretKey);
    const tampered = new TextEncoder().encode('tess');
    expect(verify(sig, tampered, kp.publicKey)).toBe(false);
  });

  it('different keypairs produce different signatures for same message', () => {
    const kp1 = generateSigningKeyPair();
    const kp2 = generateSigningKeyPair();
    const msg = new TextEncoder().encode('same message');
    const sig1 = sign(msg, kp1.secretKey);
    const sig2 = sign(msg, kp2.secretKey);
    expect(Array.from(sig1)).not.toEqual(Array.from(sig2));
  });
});

describe('sign + verify input validation', () => {
  it('sign throws on wrong-size secret key', () => {
    const msg = new TextEncoder().encode('test');
    expect(() => sign(msg, new Uint8Array(32))).toThrow(InvalidInputError);
  });

  it('verify throws on wrong-size public key', () => {
    const kp = generateSigningKeyPair();
    const msg = new TextEncoder().encode('test');
    const sig = sign(msg, kp.secretKey);
    expect(() => verify(sig, msg, new Uint8Array(32))).toThrow(InvalidInputError);
  });

  it('verify throws on wrong-size signature', () => {
    const kp = generateSigningKeyPair();
    const msg = new TextEncoder().encode('test');
    expect(() => verify(new Uint8Array(64), msg, kp.publicKey)).toThrow(InvalidInputError);
  });
});

describe('constants', () => {
  it('exports correct constants', () => {
    expect(ALGORITHM_ID).toBe('ML-DSA-65');
    expect(PUBLIC_KEY_BYTES).toBe(1952);
    expect(SECRET_KEY_BYTES).toBe(4032);
    expect(SIGNATURE_BYTES).toBe(3309);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/ml-dsa.test.ts`
Expected: FAIL — `src/sig/ml-dsa.js` does not exist yet.

- [ ] **Step 3: Implement `src/sig/ml-dsa.ts`**

Create `src/sig/ml-dsa.ts`:

```typescript
/**
 * ML-DSA-65 digital signature module (NIST FIPS 204, Security Level 3).
 *
 * Thin wrapper around @noble/post-quantum/ml-dsa.js.
 * All functions are synchronous — ML-DSA is pure computation, no Web Crypto.
 *
 * References:
 * - NIST FIPS 204 (August 2024) — ML-DSA standard
 * - IETF draft-ietf-pquip-pqc-engineers — PQC for engineers
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type { SigningKeyPair } from '../types.js';
import { InvalidInputError } from '../errors.js';

export const ALGORITHM_ID = 'ML-DSA-65';
export const PUBLIC_KEY_BYTES = 1952;
export const SECRET_KEY_BYTES = 4032;
export const SIGNATURE_BYTES = 3309;

/**
 * Generate an ML-DSA-65 signing keypair.
 * Uses the library's internal CSPRNG (crypto.getRandomValues).
 */
export function generateSigningKeyPair(): SigningKeyPair {
  const kp = ml_dsa65.keygen();
  return {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
    algorithmId: ALGORITHM_ID,
  };
}

/**
 * Sign a message with an ML-DSA-65 secret key.
 * @param message - Arbitrary-length message to sign.
 * @param secretKey - 4,032-byte ML-DSA-65 secret key.
 * @returns 3,309-byte signature.
 * @throws InvalidInputError if secretKey is wrong size.
 */
export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== SECRET_KEY_BYTES) {
    throw new InvalidInputError(
      `secretKey must be ${String(SECRET_KEY_BYTES)} bytes, got ${String(secretKey.length)}`,
    );
  }
  return ml_dsa65.sign(message, secretKey);
}

/**
 * Verify an ML-DSA-65 signature.
 * @returns true if valid, false if invalid. Never throws for invalid signatures.
 * @throws InvalidInputError if publicKey or signature is wrong size.
 */
export function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (publicKey.length !== PUBLIC_KEY_BYTES) {
    throw new InvalidInputError(
      `publicKey must be ${String(PUBLIC_KEY_BYTES)} bytes, got ${String(publicKey.length)}`,
    );
  }
  if (signature.length !== SIGNATURE_BYTES) {
    throw new InvalidInputError(
      `signature must be ${String(SIGNATURE_BYTES)} bytes, got ${String(signature.length)}`,
    );
  }
  try {
    return ml_dsa65.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/ml-dsa.test.ts`
Expected: All 12 tests PASS.

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `npx vitest run`
Expected: All existing tests still pass (176 + 12 new = 188).

- [ ] **Step 6: Commit**

```bash
git add src/sig/ml-dsa.ts test/ml-dsa.test.ts
git commit -m "feat(sig): add ML-DSA-65 signing module with keygen, sign, verify"
```

---

### Task 3: Shard Encryption Module

**Files:**
- Create: `src/sss/shard-encrypt.ts`
- Test: `test/shard-encrypt.test.ts`

**Context:** This module composes three existing pieces:
1. **HPKE** (`src/hpke.ts`): `sealBase(kem, pkR, info, aad, plaintext)` → `{ enc, ciphertext, iv, tag }` and `openBase(kem, enc, skR, info, aad, ct)` → plaintext. These are async.
2. **ML-DSA-65** (`src/sig/ml-dsa.ts` from Task 2): `sign(message, secretKey)` and `verify(signature, message, publicKey)`. These are sync.
3. **Types** (`src/types.ts`): `Shard` has `{ index: number, value: Uint8Array(32), mac: Uint8Array(32) }`. `EncryptedShard` from Task 1.

**The KEM interface** (`src/kem/kem.ts`): `Kem` has `id`, `publicKeySize`, `privateKeySize`, `encSize`, `sharedSecretSize`, plus `generateKeyPair()`, `encapsulate(pk)`, `decapsulate(enc, sk)`.

**Default KEM** is `HYBRID_X25519_MLKEM768` from `src/kem/hybrid-kem.js`. Public key = 1,216 bytes, private key = 2,464 bytes.

**Serialization format:** `[index: 1 byte][value: 32 bytes][mac: 32 bytes]` = 65 bytes fixed.

**Signed plaintext:** `[serialized shard: 65 bytes][ML-DSA-65 signature: 3,309 bytes]` = 3,374 bytes.

- [ ] **Step 1: Write the failing tests in `test/shard-encrypt.test.ts`**

Create `test/shard-encrypt.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import { distributeShard, recoverShard } from '../src/sss/shard-encrypt.js';
import { splitKey } from '../src/sss/key-split.js';
import { combineShards } from '../src/sss/key-split.js';
import { generateSigningKeyPair } from '../src/sig/ml-dsa.js';
import { generateMasterKeyPair } from '../src/key-wrap.js';
import { DHKEM_X25519 } from '../src/kem/dhkem-x25519.js';
import {
  AuthenticationError,
  InvalidInputError,
  SignatureVerificationError,
} from '../src/errors.js';

describe('distributeShard + recoverShard round-trip', () => {
  it('full round-trip: splitKey → distribute → recover → combineShards', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 3, shares: 5 });

    const ownerSig = generateSigningKeyPair();

    // Encrypt each shard for a different custodian
    const custodians = await Promise.all(
      shards.map(() => generateMasterKeyPair()),
    );

    const encrypted = await Promise.all(
      shards.map((shard, i) =>
        distributeShard(shard, custodians[i]!.publicKey, ownerSig.secretKey),
      ),
    );

    // Recover 3 of 5
    const recovered = await Promise.all(
      [0, 2, 4].map((i) =>
        recoverShard(encrypted[i]!, custodians[i]!.privateKey, ownerSig.publicKey),
      ),
    );

    const result = await combineShards(recovered);
    expect(Array.from(result)).toEqual(Array.from(secret));
  });

  it('round-trip with DHKEM-X25519', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );
    expect(encrypted.kemId).toBe('DHKEM-X25519-HKDF-SHA256');

    const recovered = await recoverShard(
      encrypted,
      custodian.privateKey,
      ownerSig.publicKey,
      { kem: DHKEM_X25519 },
    );
    expect(recovered.index).toBe(shards[0]!.index);
    expect(Array.from(recovered.value)).toEqual(Array.from(shards[0]!.value));
    expect(Array.from(recovered.mac)).toEqual(Array.from(shards[0]!.mac));
  });

  it('round-trip with HPKE info parameter', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);
    const info = new TextEncoder().encode('sample-id-001');

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519, info },
    );

    const recovered = await recoverShard(
      encrypted,
      custodian.privateKey,
      ownerSig.publicKey,
      { kem: DHKEM_X25519, info },
    );
    expect(recovered.index).toBe(shards[0]!.index);
  });

  it('preserves shard integrity (index, value, mac)', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });
    const shard = shards[0]!;

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shard,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );
    const recovered = await recoverShard(
      encrypted,
      custodian.privateKey,
      ownerSig.publicKey,
      { kem: DHKEM_X25519 },
    );

    expect(recovered.index).toBe(shard.index);
    expect(Array.from(recovered.value)).toEqual(Array.from(shard.value));
    expect(Array.from(recovered.mac)).toEqual(Array.from(shard.mac));
  });

  it('different custodians get different encrypted shards', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const c1 = await generateMasterKeyPair(DHKEM_X25519);
    const c2 = await generateMasterKeyPair(DHKEM_X25519);

    const e1 = await distributeShard(
      shards[0]!,
      c1.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );
    const e2 = await distributeShard(
      shards[0]!,
      c2.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    expect(Array.from(e1.enc)).not.toEqual(Array.from(e2.enc));
  });
});

describe('recoverShard error cases', () => {
  it('wrong custodian private key throws AuthenticationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const c1 = await generateMasterKeyPair(DHKEM_X25519);
    const c2 = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      c1.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    await expect(
      recoverShard(encrypted, c2.privateKey, ownerSig.publicKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('wrong owner verify key throws SignatureVerificationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig1 = generateSigningKeyPair();
    const ownerSig2 = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig1.secretKey,
      { kem: DHKEM_X25519 },
    );

    await expect(
      recoverShard(encrypted, custodian.privateKey, ownerSig2.publicKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(SignatureVerificationError);
  });

  it('tampered ciphertext throws AuthenticationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    const tampered = new Uint8Array(encrypted.ciphertext);
    tampered[0] ^= 0x01;

    await expect(
      recoverShard(
        { ...encrypted, ciphertext: tampered },
        custodian.privateKey,
        ownerSig.publicKey,
        { kem: DHKEM_X25519 },
      ),
    ).rejects.toThrow(AuthenticationError);
  });

  it('tampered enc throws AuthenticationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    const tampered = new Uint8Array(encrypted.enc);
    tampered[0] ^= 0x01;

    await expect(
      recoverShard(
        { ...encrypted, enc: tampered },
        custodian.privateKey,
        ownerSig.publicKey,
        { kem: DHKEM_X25519 },
      ),
    ).rejects.toThrow(AuthenticationError);
  });

  it('tampered tag throws AuthenticationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    const tampered = new Uint8Array(encrypted.tag);
    tampered[0] ^= 0x01;

    await expect(
      recoverShard(
        { ...encrypted, tag: tampered },
        custodian.privateKey,
        ownerSig.publicKey,
        { kem: DHKEM_X25519 },
      ),
    ).rejects.toThrow(AuthenticationError);
  });

  it('KEM ID mismatch throws InvalidInputError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair();

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
    );

    // Try to recover with DHKEM-X25519 but encrypted with hybrid
    await expect(
      recoverShard(encrypted, custodian.privateKey, ownerSig.publicKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });
});

describe('distributeShard input validation', () => {
  it('invalid shard value size throws InvalidInputError', async () => {
    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const badShard = { index: 1, value: new Uint8Array(16), mac: new Uint8Array(32) };
    await expect(
      distributeShard(badShard, custodian.publicKey, ownerSig.secretKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('invalid shard mac size throws InvalidInputError', async () => {
    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const badShard = { index: 1, value: new Uint8Array(32), mac: new Uint8Array(16) };
    await expect(
      distributeShard(badShard, custodian.publicKey, ownerSig.secretKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('invalid ownerSigningKey size throws InvalidInputError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    await expect(
      distributeShard(shards[0]!, custodian.publicKey, new Uint8Array(32), { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('invalid ownerVerifyKey size throws InvalidInputError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    await expect(
      recoverShard(encrypted, custodian.privateKey, new Uint8Array(32), { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/shard-encrypt.test.ts`
Expected: FAIL — `src/sss/shard-encrypt.js` does not exist yet.

- [ ] **Step 3: Implement `src/sss/shard-encrypt.ts`**

Create `src/sss/shard-encrypt.ts`:

```typescript
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/shard-encrypt.test.ts`
Expected: All 15 tests PASS.

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `npx vitest run`
Expected: All tests pass (188 + 15 = 203).

- [ ] **Step 6: Commit**

```bash
git add src/sss/shard-encrypt.ts test/shard-encrypt.test.ts
git commit -m "feat(sss): add shard encryption with ML-DSA-65 signing and HPKE encryption"
```

---

### Task 4: Public API Exports

**Files:**
- Modify: `src/index.ts`
- Modify: `test/public-api.test.ts`

- [ ] **Step 1: Update `test/public-api.test.ts` with v0.4 exports**

Open `test/public-api.test.ts`. In the `expected` set inside the `'exports exactly the expected symbols'` test, add these entries (after the v0.3 block and before the Errors block):

```typescript
      // v0.4 — Shard encryption + ML-DSA-65 signing
      'generateSigningKeyPair',
      'sign',
      'verify',
      'distributeShard',
      'recoverShard',
      'SignatureVerificationError',
```

Add `SignatureVerificationError` to the Errors section if not already there — it should be alongside the other error exports.

In the `'does not expose test-only or internal symbols'` test, add these to the `forbidden` array:

```typescript
      // ML-DSA internals
      'ml_dsa65',
      'ALGORITHM_ID',
      'PUBLIC_KEY_BYTES',
      'SECRET_KEY_BYTES',
      'SIGNATURE_BYTES',
      // Shard encryption internals
      'serializeShard',
      'deserializeShard',
      'SERIALIZED_SHARD_BYTES',
      'SHARD_VALUE_BYTES',
      'SHARD_MAC_BYTES',
```

The full updated test file should look like this:

```typescript
import { describe, expect, it } from 'vitest';
import * as api from '../src/index.js';

describe('public API surface', () => {
  it('exports exactly the expected symbols', () => {
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
      // v0.4 — Shard encryption + ML-DSA-65 signing
      'generateSigningKeyPair',
      'sign',
      'verify',
      'distributeShard',
      'recoverShard',
      // Errors
      'EternisCryptoError',
      'AuthenticationError',
      'KeyExhaustedError',
      'InvalidInputError',
      'DecapsulationError',
      'KeyWrappingError',
      'ShardAuthenticationError',
      'SignatureVerificationError',
    ]);
    const actual = new Set(Object.keys(api));
    expect(actual).toEqual(expected);
  });

  it('does not expose test-only or internal symbols', () => {
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
      // ML-DSA internals
      'ml_dsa65',
      'ALGORITHM_ID',
      'PUBLIC_KEY_BYTES',
      'SECRET_KEY_BYTES',
      'SIGNATURE_BYTES',
      // Shard encryption internals
      'serializeShard',
      'deserializeShard',
      'SERIALIZED_SHARD_BYTES',
      'SHARD_VALUE_BYTES',
      'SHARD_MAC_BYTES',
    ];
    for (const name of forbidden) {
      expect(Object.keys(api)).not.toContain(name);
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/public-api.test.ts`
Expected: FAIL — `sign`, `verify`, `generateSigningKeyPair`, `distributeShard`, `recoverShard`, `SignatureVerificationError` not yet exported from `src/index.ts`.

- [ ] **Step 3: Update `src/index.ts` with v0.4 exports**

Open `src/index.ts`. After the v0.3 block (`export { splitKey, combineShards }`) and before the `// Shared errors` block, add:

```typescript
// v0.4 — Shard encryption + ML-DSA-65 signing
export type { SigningKeyPair, EncryptedShard } from './types.js';
export { generateSigningKeyPair, sign, verify } from './sig/ml-dsa.js';
export { distributeShard, recoverShard } from './sss/shard-encrypt.js';
```

In the shared errors export block, add `SignatureVerificationError` to the list:

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
  SignatureVerificationError,
} from './errors.js';
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/public-api.test.ts`
Expected: PASS — all expected exports present, no forbidden internals exposed.

- [ ] **Step 5: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass (203 + updated public-api = 203 total, no new test count since public-api already existed).

- [ ] **Step 6: Commit**

```bash
git add src/index.ts test/public-api.test.ts
git commit -m "feat(api): export v0.4 shard encryption and ML-DSA-65 signing"
```

---

### Task 5: Version Bump

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Bump version in `package.json`**

Open `package.json`. Change `"version": "0.3.0"` to `"version": "0.4.0"`.

- [ ] **Step 2: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass.

- [ ] **Step 3: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add package.json
git commit -m "chore: bump version to 0.4.0"
```

---

### Task 6: Final Verification

**Files:** None — this is a verification-only task.

- [ ] **Step 1: Run the complete test suite**

Run: `npx vitest run`
Expected: All tests pass. Total should be approximately 203 tests (176 existing + 12 ML-DSA + 15 shard-encrypt).

- [ ] **Step 2: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Run lint**

Run: `npx eslint src test --ext .ts`
Expected: No errors. If there are lint warnings about `@typescript-eslint/require-await`, that's expected — `distributeShard` and `recoverShard` are properly async (they call HPKE which is async). The ML-DSA functions are sync and should not have this warning.

- [ ] **Step 4: Verify git log**

Run: `git log --oneline -6`
Expected: 4-5 commits from this implementation, clean history.
