# Shard Encryption — Design Spec

## Summary

Add shard encryption to `eternis-crypto` as the fourth cryptographic primitive (v0.4.0). Before distributing a Shamir shard to a custodian, encrypt it under that custodian's HPKE public key and sign it with the data owner's ML-DSA-65 private key. This ensures only the intended custodian can read their shard, and the custodian can verify the shard's origin.

**Approach:** Sign-then-encrypt using ML-DSA-65 (NIST FIPS 204, Security Level 3) for origin authentication and HPKE Base mode (RFC 9180, hybrid X25519 + ML-KEM-768 default) for confidentiality. The signature is placed inside the encryption envelope so observers cannot link owner to shard.

**Research basis:**
- PreVeil 2024 Security Whitepaper — deployed shard encryption under approver public keys with authenticated encryption + signing (FIPS 140-2 cert #3804)
- NIST FIPS 204 (August 2024) — ML-DSA standard for post-quantum digital signatures
- LINCOS / Braun 2017 — information-theoretically secure shard transport via QKD+OTP (future upgrade path)
- Alwen et al. 2021 (EUROCRYPT) — formal security proofs for HPKE IND-CCA2

**Design principle:** Post-quantum from day one. ML-DSA-65 (signing) matches ML-KEM-768 (encryption) at NIST Security Level 3 across the entire stack. The Mosca model from the IETF PQC engineers' guide recommends post-quantum signatures now for data that must remain secure past 2040.

**Future upgrade path:** The API is designed with a pluggable transport layer. When QKD hardware becomes available, the HPKE encryption can be replaced with OTP over QKD channels (LINCOS pattern) without changing the Shamir splitting or the public API contract.

**Non-goals (future phases):**
- Custodian identity management and key distribution (Vault platform layer)
- Shard storage and retrieval (Vault platform layer)
- Proactive resharing (v0.5 — LINCOS-style periodic shard rotation)
- Key rotation for custodian keys (application layer)
- QKD transport (requires hardware; API designed for future swap)

## Architecture

Two new internal modules, one extended public API surface:

```
src/sig/ml-dsa.ts            (ML-DSA-65 signing: keygen, sign, verify)
    ↓ used by
src/sss/shard-encrypt.ts     (Public API: distributeShard, recoverShard)
    ↓ also uses
src/key-wrap.ts / src/hpke.ts (HPKE encryption, already built in v0.2)
src/sss/key-split.ts         (Shard type, already built in v0.3)
```

### Data Flow — Distribute

```
splitKey() produces Shard (v0.3)
    ↓
distributeShard(shard, custodianPublicKey, ownerSigningKey)
    ↓ step 1: serialize
    index (1 byte) || value (32 bytes) || mac (32 bytes) = 65 bytes
    ↓ step 2: sign
    ML-DSA-65 signature over serialized shard = 3,309 bytes
    ↓ step 3: build plaintext
    serialized shard (65 bytes) || signature (3,309 bytes) = 3,374 bytes
    ↓ step 4: encrypt
    HPKE seal under custodian's public key
    ↓
EncryptedShard (opaque blob only the custodian can open)
```

### Data Flow — Recover

```
recoverShard(encryptedShard, custodianPrivateKey, ownerVerifyKey)
    ↓ step 1: decrypt
    HPKE open with custodian's private key → 3,374 bytes plaintext
    ↓ step 2: split
    serialized shard (65 bytes) + signature (3,309 bytes)
    ↓ step 3: verify signature
    ML-DSA-65 verify(signature, serializedShard, ownerVerifyKey)
    ↓ step 4: deserialize
    Reconstruct Shard { index, value, mac }
    ↓
Shard — ready for combineShards()
```

### Sign-then-Encrypt Rationale

The signature is placed inside the HPKE encryption envelope (sign-then-encrypt, not encrypt-then-sign). This follows the PreVeil pattern where "the shard is encrypted with authenticated encryption using the approver's public key and the user's private signing key" (PreVeil Whitepaper v1.6, Section 4.2). Benefits:

1. **Privacy:** An observer (including the storage server) cannot see the owner's signature or link it to a specific owner.
2. **Signer-intended confidentiality:** The owner signs with the knowledge that only the intended custodian will see the shard.
3. **No signature stripping:** An attacker cannot remove the signature without breaking HPKE decryption first.

## File Structure

### New files

| File | Responsibility | Approximate size |
|---|---|---|
| `src/sig/ml-dsa.ts` | ML-DSA-65 wrapper: keygen, sign, verify | ~60 lines |
| `src/sss/shard-encrypt.ts` | Public API: distributeShard, recoverShard, serialization | ~120 lines |
| `test/ml-dsa.test.ts` | ML-DSA-65 keygen, sign, verify, error cases | ~80 lines |
| `test/shard-encrypt.test.ts` | Round-trip, tampering, wrong keys, error cases | ~120 lines |

### Modified files

| File | Change |
|---|---|
| `src/index.ts` | Add v0.4 exports: generateSigningKeyPair, sign, verify, distributeShard, recoverShard, SigningKeyPair, EncryptedShard, SignatureVerificationError |
| `src/errors.ts` | Add SignatureVerificationError class |
| `src/types.ts` | Add SigningKeyPair, EncryptedShard interfaces |
| `test/public-api.test.ts` | Add v0.4 export assertions, add ML-DSA internals to forbidden list |
| `package.json` | Bump version to 0.4.0 |

## ML-DSA-65 Signing Module

### Why ML-DSA-65

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| NIST Security Level | 2 (128-bit) | **3 (192-bit)** | 5 (256-bit) |
| Public key | 1,312 bytes | **1,952 bytes** | 2,592 bytes |
| Secret key | 2,560 bytes | **4,032 bytes** | 4,896 bytes |
| Signature | 2,420 bytes | **3,309 bytes** | 4,627 bytes |

**Choice: ML-DSA-65.** Matches ML-KEM-768 at NIST Security Level 3 — consistent security level across the entire stack (encryption AND signing). ML-DSA-44 would be adequate but inconsistent. ML-DSA-87 adds ~40% overhead for marginal benefit.

### Implementation

Thin wrapper around `@noble/post-quantum/ml-dsa.js` (already installed as a dependency). Follows the same wrapping pattern as `src/kem/dhkem-x25519.ts`.

**Sync vs async:** `generateSigningKeyPair`, `sign`, and `verify` are all synchronous functions. ML-DSA is pure computation (no Web Crypto API calls), so there is no reason to make them async. This differs from the KEM and HPKE functions which use `crypto.subtle` (async). `distributeShard` and `recoverShard` are async because they call HPKE internally.

**Note on `@noble/post-quantum` API:** The sign function takes `(message, secretKey)` and verify takes `(signature, message, publicKey)` — message-first convention. Our wrapper normalizes this to a consistent interface.

### Functions

```typescript
/**
 * Generate an ML-DSA-65 signing keypair.
 * Uses crypto.getRandomValues() for seed generation.
 */
export function generateSigningKeyPair(): SigningKeyPair

/**
 * Sign a message with an ML-DSA-65 secret key.
 * @param message - Arbitrary-length message to sign.
 * @param secretKey - 4,032-byte ML-DSA-65 secret key.
 * @returns 3,309-byte signature.
 * @throws InvalidInputError if secretKey is wrong size.
 */
export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array

/**
 * Verify an ML-DSA-65 signature.
 * @returns true if valid, false if invalid. Never throws for invalid signatures.
 * @throws InvalidInputError if publicKey or signature is wrong size.
 */
export function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean
```

### Constants

| Constant | Value | Source |
|---|---|---|
| `ALGORITHM_ID` | `"ML-DSA-65"` | NIST FIPS 204 |
| `PUBLIC_KEY_BYTES` | 1,952 | NIST FIPS 204 Table 1 |
| `SECRET_KEY_BYTES` | 4,032 | NIST FIPS 204 Table 1 |
| `SIGNATURE_BYTES` | 3,309 | NIST FIPS 204 Table 1 |

### Internal exports

`ml-dsa.ts` exports `generateSigningKeyPair`, `sign`, `verify`, and size constants. All are re-exported from `src/index.ts` (signing is a general-purpose primitive useful beyond shards).

## Shard Encryption Module

### Serialization Format

Shards are serialized to a fixed 65-byte format before signing:

```
[index: 1 byte] [value: 32 bytes] [mac: 32 bytes]
```

- `index` is the shard's polynomial evaluation point (1–255), stored as a single byte.
- `value` is the 32-byte shard value (y-coordinate in GF(p)).
- `mac` is the 32-byte HMAC-SHA256 authentication tag from v0.3.

The signed plaintext is then:

```
[serialized shard: 65 bytes] [ML-DSA-65 signature: 3,309 bytes]
```

Total plaintext before HPKE encryption: **3,374 bytes**.

### Functions

```typescript
/**
 * Encrypt and sign a shard for distribution to a custodian.
 *
 * Signs the shard with the owner's ML-DSA-65 key (origin proof),
 * then encrypts under the custodian's HPKE public key (confidentiality).
 *
 * @param shard - A Shard from splitKey().
 * @param custodianPublicKey - Custodian's HPKE public key.
 * @param ownerSigningKey - Data owner's ML-DSA-65 secret key.
 * @param options - Optional KEM override and HPKE info parameter.
 * @returns EncryptedShard — opaque blob for the custodian.
 * @throws InvalidInputError if inputs fail validation.
 */
export async function distributeShard(
  shard: Shard,
  custodianPublicKey: Uint8Array,
  ownerSigningKey: Uint8Array,
  options?: { kem?: Kem; info?: Uint8Array },
): Promise<EncryptedShard>

/**
 * Decrypt and verify a shard received from storage/transport.
 *
 * Decrypts with the custodian's HPKE private key, then verifies
 * the owner's ML-DSA-65 signature to confirm origin.
 *
 * @param encryptedShard - An EncryptedShard from distributeShard().
 * @param custodianPrivateKey - Custodian's HPKE private key.
 * @param ownerVerifyKey - Data owner's ML-DSA-65 public key.
 * @param options - Optional KEM override and HPKE info parameter.
 * @returns The original Shard, ready for combineShards().
 * @throws AuthenticationError if HPKE decryption fails (wrong key or tampered).
 * @throws SignatureVerificationError if ML-DSA-65 signature is invalid.
 * @throws InvalidInputError if inputs fail validation.
 */
export async function recoverShard(
  encryptedShard: EncryptedShard,
  custodianPrivateKey: Uint8Array,
  ownerVerifyKey: Uint8Array,
  options?: { kem?: Kem; info?: Uint8Array },
): Promise<Shard>
```

### HPKE Usage

Shard encryption reuses the existing HPKE `sealBase` / `openBase` functions from `src/hpke.ts`. The 3,374-byte signed shard becomes the HPKE plaintext. AAD is empty (shard metadata is inside the signed envelope). The `info` parameter is available for application-layer context binding.

**Default KEM:** Hybrid-X25519-MLKEM768 (same post-quantum default as v0.2).

**Pluggable KEM:** The `options.kem` parameter allows DHKEM-X25519 or future KEM implementations, following the same pattern as `wrapKey()`.

## Types

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

## Validation Rules

| Parameter | Rule | Error |
|---|---|---|
| `shard` (distribute) | Must have index 1–255, value 32 bytes, mac 32 bytes | `InvalidInputError` |
| `custodianPublicKey` (distribute) | Must match KEM's public key size | `InvalidInputError` |
| `ownerSigningKey` (distribute) | Must be 4,032 bytes (ML-DSA-65 secret key) | `InvalidInputError` |
| `encryptedShard` (recover) | All fields must be present and non-empty | `InvalidInputError` |
| `custodianPrivateKey` (recover) | HPKE decryption fails → `AuthenticationError` | `AuthenticationError` |
| `ownerVerifyKey` (recover) | Must be 1,952 bytes (ML-DSA-65 public key) | `InvalidInputError` |
| Signature verification (recover) | ML-DSA-65 verify returns false | `SignatureVerificationError` |
| KEM ID mismatch (recover) | encryptedShard.kemId vs options.kem.id | `InvalidInputError` |

## Error Classes

```typescript
/** Thrown when ML-DSA-65 signature verification fails during shard recovery. */
export class SignatureVerificationError extends EternisCryptoError {}
```

## Exports from `src/index.ts`

```typescript
// v0.4 — Shard encryption + ML-DSA-65 signing
export type { SigningKeyPair, EncryptedShard } from './types.js';
export { generateSigningKeyPair, sign, verify } from './sig/ml-dsa.js';
export { distributeShard, recoverShard } from './sss/shard-encrypt.js';
export { SignatureVerificationError } from './errors.js';
```

## Testing Strategy

### ml-dsa.test.ts (~12 tests)

- Keygen produces correct sizes (pk: 1,952, sk: 4,032)
- AlgorithmId is "ML-DSA-65"
- Sign/verify round-trip with small message
- Sign/verify round-trip with large message (1 MB)
- Sign/verify round-trip with empty message
- Wrong public key → verify returns false
- Tampered signature → verify returns false
- Tampered message → verify returns false
- Different keypairs produce different signatures for same message
- Same keypair signing same message twice may produce different signatures (ML-DSA is randomized)
- Wrong-size secret key → InvalidInputError
- Wrong-size public key → InvalidInputError

### shard-encrypt.test.ts (~15 tests)

- Full round-trip: splitKey → distributeShard → recoverShard → combineShards recovers secret
- Full round-trip with DHKEM-X25519 (non-default KEM)
- Full round-trip with HPKE info parameter
- Shard integrity: recovered shard has same index, value, mac as original
- Different custodians get different EncryptedShards (different HPKE encapsulations)
- Wrong custodian private key → AuthenticationError
- Wrong owner verify key → SignatureVerificationError
- Tampered ciphertext → AuthenticationError
- Tampered enc → AuthenticationError
- Tampered tag → AuthenticationError
- KEM ID mismatch → InvalidInputError
- Invalid shard (value not 32 bytes) → InvalidInputError
- Invalid shard (mac not 32 bytes) → InvalidInputError
- Invalid ownerSigningKey size → InvalidInputError
- Invalid ownerVerifyKey size → InvalidInputError

### public-api.test.ts (update existing)

- Add v0.4 exports: `generateSigningKeyPair`, `sign`, `verify`, `distributeShard`, `recoverShard`, `SignatureVerificationError`
- Add ML-DSA internals to forbidden list: `ml_dsa65`, `ALGORITHM_ID`, `PUBLIC_KEY_BYTES`, `SECRET_KEY_BYTES`, `SIGNATURE_BYTES`, `serializeShard`, `deserializeShard`

## Security Properties

| Property | Guarantee | Basis |
|---|---|---|
| Custodian confidentiality | Only the intended custodian can decrypt their shard | HPKE IND-CCA2 (Alwen et al. 2021, EUROCRYPT) |
| Origin authentication | Custodian can cryptographically verify the shard came from the data owner | ML-DSA-65 EUF-CMA (NIST FIPS 204) |
| Post-quantum safety | Both encryption and signing resist quantum attacks | ML-KEM-768 (NIST Level 3) + ML-DSA-65 (NIST Level 3) |
| Consistent security level | Encryption and signing at same NIST level — no weak link | ML-KEM-768 and ML-DSA-65 both NIST Security Level 3 |
| Shamir secrecy preserved | Encryption does not weaken the information-theoretic k-1 property | Shamir secrecy is unconditional; encryption adds computational confidentiality on top |
| Sign-then-encrypt privacy | Signature hidden inside HPKE envelope; observer cannot link owner to shard | PreVeil pattern (Whitepaper v1.6, Section 4.2) |
| Defense in depth (3 layers) | HMAC on shard (v0.3) + GCM tag on ciphertext (HPKE) + ML-DSA signature | Independent protection mechanisms |
| Pluggable transport | API designed for future QKD+OTP swap without changing Shamir or public contract | LINCOS architecture pattern (Braun 2017) |

## Dependencies

**No new dependencies.** All functionality uses:
- `@noble/post-quantum/ml-dsa.js` (already in `package.json` as `@noble/post-quantum ^0.6.1`)
- Existing HPKE implementation (`src/hpke.ts`, `src/kem/`)
- Existing Shamir types (`src/types.ts`)

## Version

Bump `package.json` version from `0.3.0` to `0.4.0`.
