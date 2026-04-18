# Preservation Pipeline Design Spec

## Overview

A single `preserve()` / `recover()` API that chains all four crypto primitives (AES-256-GCM, HPKE key wrapping, Shamir key splitting, shard encryption) into one operation. This is the top-level entry point for the eternis-crypto library.

**Version:** 0.5.0

## Research Basis

| Principle | Source | How Applied |
|-----------|--------|-------------|
| Fresh key per file | Crypt4GH (GA4GH), PreVeil, NIST SP 800-56C | `preserve()` generates ephemeral HPKE keypair internally; never reused |
| Compose primitives, don't rebuild | PreVeil whitepaper | Pipeline calls existing `encryptChunk`, `wrapKey`, `splitKey`, `distributeShard` |
| 64KB chunking for large files | Crypt4GH spec, Sousa et al. | Deferred to future version; output format is chunk-ready (array of encrypted chunks) |
| Sign-then-encrypt for shards | PreVeil whitepaper | Uses existing `distributeShard` (ML-DSA-65 + HPKE) |
| 3-of-5 threshold default | Crypt4GH examples, PreVeil enterprise recommendation | Default threshold=3, totalShards=custodianPublicKeys.length |
| Compartmentalized sharing | PreVeil Approval Groups, academic literature | Deferred to future version; flat Shamir for v0.5.0 |
| Fail loudly on all errors | Crypt4GH, PreVeil | Specific error types for every failure mode, no silent failures |

## Decisions

### Batch-only for v0.5.0

The pipeline accepts a complete `Uint8Array`. Streaming (64KB chunking) is deferred. The `PreservationPackage.encryptedData` field supports a future upgrade to multiple chunks without breaking the format. The crypto math is identical per-chunk — streaming is purely an I/O concern.

### Fresh ephemeral keypair (forward secrecy)

`preserve()` generates a fresh HPKE keypair internally. The public key wraps the DEK, the private key is Shamir-split among custodians. This provides forward secrecy — compromising one package does not affect others. The owner only passes in their ML-DSA-65 signing key (for shard authentication).

### Custodians bring their own keys

Custodian HPKE public keys are passed into `preserve()`. The pipeline does not generate custodian keys. A test helper can generate sample keys for demos/tests.

### Flat 3-of-5 Shamir (compartmentalized sharing deferred)

v0.5.0 uses standard (k, n) Shamir where all shards are equal. Compartmentalized sharing (non-negotiable holders enforced at the crypto level via two-level Shamir composition, per PreVeil's Approval Groups model) is a future primitive.

## API

### `preserve()`

```typescript
async function preserve(
  data: Uint8Array,
  custodianPublicKeys: Uint8Array[],
  ownerSigningKey: Uint8Array,
  options?: {
    threshold?: number;   // default 3
    kem?: Kem;            // default HYBRID_X25519_MLKEM768
  }
): Promise<PreservationPackage>
```

**Parameters:**
- `data` — raw data to preserve (must be non-empty)
- `custodianPublicKeys` — one HPKE public key per custodian (length must be >= threshold)
- `ownerSigningKey` — ML-DSA-65 secret key for signing shards
- `options.threshold` — minimum shards needed to recover (default 3)
- `options.kem` — KEM algorithm for HPKE operations (default hybrid)

**Internal flow:**
1. Validate inputs (data non-empty, custodianPublicKeys.length >= threshold, signing key valid size)
2. Generate DEK via `encryptChunk(data)` — returns `{ ciphertext, iv, tag, key }`
3. Generate fresh HPKE keypair via KEM
4. Wrap DEK under fresh HPKE public key via `wrapKey()`
5. Split fresh HPKE private key via `splitKey(privateKey, threshold, custodianPublicKeys.length)`
6. For each shard + custodian: `distributeShard(shard, custodianPublicKey, ownerSigningKey)`
7. Securely erase DEK and HPKE private key from memory
8. Return `PreservationPackage`

### `recover()`

```typescript
async function recover(
  pkg: PreservationPackage,
  custodianPrivateKeys: { index: number; privateKey: Uint8Array }[],
  ownerVerifyKey: Uint8Array,
  options?: { kem?: Kem }
): Promise<Uint8Array>
```

**Parameters:**
- `pkg` — the `PreservationPackage` returned by `preserve()`
- `custodianPrivateKeys` — at least `threshold` custodian HPKE private keys, each paired with the index of the corresponding encrypted shard in `pkg.encryptedShards` (positional index, 0-based)
- `ownerVerifyKey` — ML-DSA-65 public key to verify shard signatures
- `options.kem` — KEM algorithm (must match what was used in `preserve()`)

**Internal flow:**
1. Validate inputs (enough custodian keys to meet threshold)
2. For each custodian: `recoverShard(encryptedShard, custodianPrivateKey, ownerVerifyKey)` — decrypts and verifies signature
3. Combine recovered shards via `combineShards()` — reconstructs HPKE private key
4. Unwrap DEK via `unwrapKey(wrappedKey, hpkePrivateKey)`
5. Decrypt data via `decryptChunk(ciphertext, dek, iv)`
6. Securely erase reconstructed HPKE private key and DEK from memory
7. Return original data

### `PreservationPackage`

```typescript
interface PreservationPackage {
  readonly encryptedData: {
    readonly ciphertext: Uint8Array;
    readonly iv: Uint8Array;
    readonly tag: Uint8Array;
  };
  readonly wrappedKey: {
    readonly enc: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly iv: Uint8Array;
    readonly tag: Uint8Array;
  };
  readonly encryptedShards: EncryptedShard[];
  readonly metadata: {
    readonly version: string;
    readonly threshold: number;
    readonly totalShards: number;
    readonly kemId: string;
    readonly sigAlgorithmId: string;
  };
}
```

## Error Handling

All errors use existing error classes from `src/errors.ts`:

| Condition | Error Class | When |
|-----------|-------------|------|
| Empty data | `InvalidInputError` | `preserve()` |
| Not enough custodian keys | `InvalidInputError` | `preserve()` / `recover()` |
| Invalid signing key size | `InvalidInputError` | `preserve()` |
| Shard signature verification fails | `SignatureVerificationError` | `recover()` |
| Decryption fails (wrong key / corrupted) | `DecryptionError` | `recover()` |
| Shard combination fails (wrong shards) | `KeySplittingError` | `recover()` |

No new error classes needed. No silent failures.

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/pipeline.ts` | Create | `preserve()` and `recover()` functions |
| `src/types.ts` | Modify | Add `PreservationPackage` interface |
| `src/index.ts` | Modify | Export `preserve`, `recover`, `PreservationPackage` |
| `test/pipeline.test.ts` | Create | Pipeline composition tests |
| `test/public-api.test.ts` | Modify | Add v0.5 exports to expected set |
| `package.json` | Modify | Bump version to 0.5.0 |

## Testing Strategy

Pipeline tests validate the **composition** only. Individual primitive tests (205 existing) are not duplicated.

### Round-trip tests
- `preserve()` then `recover()` returns exact original data
- Works with default options (3-of-5, hybrid KEM)
- Works with custom threshold (2-of-3)
- Works with DHKEM-X25519 fallback KEM

### Tampering detection tests
- Tampered ciphertext → `DecryptionError`
- Tampered wrapped key → `DecryptionError`
- Tampered encrypted shard → `SignatureVerificationError` or `DecryptionError`
- Modified metadata → appropriate error

### Edge case tests
- Empty data → `InvalidInputError`
- Fewer custodian keys than threshold → `InvalidInputError`
- Fewer shards than threshold in recover → `InvalidInputError`
- Wrong custodian private key → decryption failure
- Wrong owner verify key → `SignatureVerificationError`
- Exactly threshold shards (boundary) → success
- Large data (1MB) → success

### Public API tests
- v0.5 exports present: `preserve`, `recover`, `PreservationPackage`
- Pipeline internals not exported

## Future Work (Not in v0.5.0)

1. **Streaming / chunking** — split input into 64KB chunks before encryption (Crypt4GH standard). Output format already supports multiple chunks.
2. **Compartmentalized sharing** — two-level Shamir composition enforcing non-negotiable custodians at the crypto level (PreVeil Approval Groups model).
3. **Serialization** — `PreservationPackage` to/from binary or JSON for storage and transport.
4. **Secure memory erasure** — zero out DEK and reconstructed keys after use. Noted in flow but JavaScript lacks guaranteed secure erasure; best-effort via `TypedArray.fill(0)`.
