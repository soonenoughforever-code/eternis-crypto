# HPKE Key Wrapping — Design Spec

**Date:** 2026-04-17
**Status:** Approved
**Primitive:** HPKE-aligned key wrapping with pluggable KEM (hybrid PQ default)
**Library:** eternis-crypto v0.2.0
**Author:** Claude (Opus 4.6) + Guillermo Rivacoba

---

## 1. Purpose

Wrap and unwrap Data Encryption Keys (DEKs) under a user's master keypair so that DEKs can be stored safely without exposing raw key material. This is the second cryptographic primitive in eternis-crypto, sitting above the AES-256-GCM chunk encryption layer (v0.1.0).

### Why HPKE

Four incompatible ECIES standards exist (ANSI X9.63, IEEE 1363a, ISO/IEC 18033-2, SECG SEC 1). RFC 9180 (HPKE) unifies them with formal security proofs (Alwen et al., EUROCRYPT 2021). Google, Cloudflare, and Apple all deploy HPKE or HPKE-aligned constructions. Following HPKE eliminates ambiguity about which ECIES variant we implement.

### Why post-quantum from day one

Genomic data must stay confidential for 30-50 years. The harvest-now-decrypt-later threat means an attacker who records today's ciphertexts can decrypt them when quantum computers arrive. Hybrid X25519 + ML-KEM-768 ensures data remains safe if either classical or post-quantum assumptions hold.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────┐
│              Public API (key-wrap.ts)        │
│   wrapKey() / unwrapKey()                   │
│   generateMasterKeyPair()                   │
├─────────────────────────────────────────────┤
│              HPKE Base Mode (hpke.ts)       │
│   SealBase() / OpenBase()                   │
│   Key schedule (LabeledExtract/Expand)      │
├──────────────┬──────────────────────────────┤
│  KEM         │  KDF          │  AEAD        │
│  (pluggable) │  (hkdf.ts)    │  (Web Crypto │
│              │               │   AES-256-   │
│              │               │   GCM)       │
├──────────────┤               │              │
│ dhkem-       │               │              │
│ x25519.ts    │               │              │
│ (classical)  │               │              │
├──────────────┤               │              │
│ hybrid-      │               │              │
│ kem.ts       │               │              │
│ (X25519 +    │               │              │
│  ML-KEM-768) │               │              │
└──────────────┴───────────────┴──────────────┘
```

**Existing code (v0.1.0) is untouched.** The HPKE AEAD calls `crypto.subtle.encrypt/decrypt` directly — it does not use `encryptChunk`/`decryptChunk`, which have invocation counters and constraints designed for data chunks, not single-shot key wrapping.

---

## 3. File Structure

```
src/
  index.ts                 (add new exports)
  types.ts                 (add WrappedKey, MasterKeyPair, KEM interfaces)
  errors.ts                (add DecapsulationError, KeyWrappingError)
  aes-gcm.ts               (UNTOUCHED)
  keys.ts                  (UNTOUCHED)
  kem/
    kem.ts                 (Kem interface definition)
    dhkem-x25519.ts        (DHKEM(X25519, HKDF-SHA256) — Web Crypto only)
    hybrid-kem.ts          (X25519 + ML-KEM-768 composite KEM)
  hkdf.ts                  (LabeledExtract, LabeledExpand, extract, expand)
  hpke.ts                  (HPKE Base mode: SealBase, OpenBase, key schedule)
  key-wrap.ts              (Public API: wrapKey, unwrapKey, generateMasterKeyPair)
  internal/
    invocation-counter.ts  (UNTOUCHED)
    random.ts              (UNTOUCHED)

test/
  hkdf.test.ts             (RFC 9180 Appendix A HKDF vectors)
  dhkem-x25519.test.ts     (RFC 9180 Appendix A DHKEM vectors + round-trip)
  hybrid-kem.test.ts       (X-Wing test vectors + round-trip + combiner)
  hpke.test.ts             (RFC 9180 Appendix A Base mode vectors)
  key-wrap.test.ts         (round-trip both KEMs, wrong-key, kemId)
  public-api.test.ts       (UPDATE: add new exports to surface check)
  vectors/
    rfc9180-dhkem-x25519.json    (extracted from RFC 9180 Appendix A)
    rfc9180-hpke-base.json       (extracted from RFC 9180 Appendix A)
    xwing-kem.json               (extracted from X-Wing paper)
```

---

## 4. KEM Interface

```typescript
interface KemKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

interface EncapsulationResult {
  sharedSecret: Uint8Array;  // 32 bytes always
  enc: Uint8Array;           // 32 bytes (DHKEM) or 1120 bytes (hybrid)
}

interface Kem {
  readonly id: string;
  readonly publicKeySize: number;
  readonly privateKeySize: number;
  readonly encSize: number;
  readonly sharedSecretSize: number;  // always 32

  generateKeyPair(): Promise<KemKeyPair>;
  encapsulate(publicKey: Uint8Array): Promise<EncapsulationResult>;
  decapsulate(enc: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
}
```

### 4.1 DHKEM-X25519 (classical)

**id:** `"DHKEM-X25519-HKDF-SHA256"`
**Spec:** RFC 9180 Section 4.1, KEM ID 0x0020
**Dependencies:** Web Crypto API only (zero external deps)

**Key sizes:**
- Public key: 32 bytes
- Private key: 32 bytes
- enc: 32 bytes (ephemeral public key)
- Shared secret: 32 bytes

**encapsulate(pkR):**
1. Generate ephemeral X25519 keypair `(skE, pkE)` via `crypto.subtle.generateKey("X25519")`
2. `DH(skE, pkR)` via `crypto.subtle.deriveBits({ name: "X25519", public: pkR }, skE, 256)`
3. `kem_context = pkE || pkR`
4. `shared_secret = ExtractAndExpand(dh, kem_context)` per RFC 9180 Section 4.1
5. Return `{ sharedSecret: shared_secret, enc: pkE }`

**decapsulate(enc, skR):**
1. `pkE = enc`
2. `DH(skR, pkE)` via `crypto.subtle.deriveBits`
3. `pkR = publicKeyFrom(skR)` — derive public key from private key
4. `kem_context = pkE || pkR`
5. `shared_secret = ExtractAndExpand(dh, kem_context)`
6. Return `shared_secret`

**ExtractAndExpand(dh, kem_context):**
- `prk = LabeledExtract("", "shared_secret", dh)` with suite_id = `"KEM" || I2OSP(0x0020, 2)`
- `shared_secret = LabeledExpand(prk, "eae_prk", kem_context, 32)`

### 4.2 Hybrid-X25519-MLKEM768

**id:** `"Hybrid-X25519-MLKEM768"`
**Spec:** NIST SP 800-227 Section 4.6 composite KEM pattern + X-Wing combiner (Barbosa et al. 2024)
**Dependencies:** `@noble/post-quantum` (ML-KEM-768), `@noble/hashes` (SHA3-256)

**Key sizes:**
- Public key: 1216 bytes (ML-KEM-768 pk 1184 + X25519 pk 32)
- Private key: 2464 bytes (ML-KEM-768 sk 2400 + X25519 sk 32 + X25519 pk 32, per X-Wing Figure 1)
- enc: 1120 bytes (ML-KEM-768 ct 1088 + X25519 ct 32)
- Shared secret: 32 bytes

**encapsulate(pk):**
1. Split `pk` into `pk_M` (1184 bytes) and `pk_X` (32 bytes)
2. `(ss_M, ct_M) = ML-KEM-768.Encaps(pk_M)` via `@noble/post-quantum`
3. Generate ephemeral X25519 keypair `(sk_X, ct_X)` via Web Crypto
4. `ss_X = DH(sk_X, pk_X)` via `crypto.subtle.deriveBits`
5. `shared_secret = SHA3-256(XWingLabel || ss_M || ss_X || ct_X || pk_X)`
   - `XWingLabel` = 6-byte ASCII `\./` + `/^\` = hex `5c2e2f2f5e5c` (from X-Wing spec, Figure 1)
6. `enc = ct_M || ct_X`
7. Return `{ sharedSecret: shared_secret, enc }`

**decapsulate(enc, sk):**
1. Split `enc` into `ct_M` (1088 bytes) and `ct_X` (32 bytes)
2. Split `sk` into `sk_M` (2400 bytes), `sk_X` (32 bytes), and `pk_X` (32 bytes)
3. `ss_M = ML-KEM-768.Decaps(ct_M, sk_M)`
4. `ss_X = DH(sk_X, ct_X)` via `crypto.subtle.deriveBits`
5. `pk_X` is already in the private key (bytes 2432..2464) — no derivation needed
6. `shared_secret = SHA3-256(XWingLabel || ss_M || ss_X || ct_X || pk_X)` where `XWingLabel` = hex `5c2e2f2f5e5c`
7. Return `shared_secret`

**Combiner rationale:** The X-Wing combiner `SHA3-256(label || ss_M || ss_X || ct_X || pk_X)` follows NIST SP 800-227's approved `KeyCombine_H^CCA` template (Section 4.6.3, Equation 15). Including `ct_X` and `pk_X` in the hash input is required for IND-CCA security — a naive `KDF(K1 || K2)` does NOT preserve IND-CCA (SP 800-227 explicitly warns against this).

---

## 5. HKDF — Labeled Extract & Expand

**File:** `src/hkdf.ts`
**Spec:** RFC 9180 Section 4, RFC 5869

Web Crypto's built-in HKDF performs Extract+Expand atomically — the steps cannot be separated. HPKE requires them separate with label prefixes. Solution: implement using `crypto.subtle.sign("HMAC", ...)` directly, same approach as hpke-js and panva/hpke.

**Exports:**

```typescript
// Low-level (RFC 5869)
extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>   // HMAC-SHA-256(salt, ikm)
expand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>

// HPKE-specific (RFC 9180 Section 4)
labeledExtract(salt: Uint8Array, label: string, ikm: Uint8Array, suiteId: Uint8Array): Promise<Uint8Array>
labeledExpand(prk: Uint8Array, label: string, info: Uint8Array, length: number, suiteId: Uint8Array): Promise<Uint8Array>
```

**LabeledExtract(salt, label, ikm, suiteId):**
1. `labeled_ikm = concat("HPKE-v1", suiteId, encode(label), ikm)`
2. Return `extract(salt, labeled_ikm)` — i.e. `HMAC-SHA-256(salt, labeled_ikm)`

**LabeledExpand(prk, label, info, L, suiteId):**
1. `labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suiteId, encode(label), info)`
2. Return `expand(prk, labeled_info, L)`

**Dependencies:** Web Crypto API only (`crypto.subtle.importKey("raw", ..., "HMAC")` + `crypto.subtle.sign("HMAC", ...)`).

---

## 6. HPKE Base Mode

**File:** `src/hpke.ts`
**Spec:** RFC 9180 Section 5.1 (Base mode, mode = 0x00)
**Cipher suite:** KEM(pluggable) + HKDF-SHA256 (KDF ID 0x0001) + AES-256-GCM (AEAD ID 0x0002)

### SealBase(kem, pkR, info, aad, plaintext)

```
1. (shared_secret, enc) = kem.encapsulate(pkR)
2. Key schedule (mode = 0x00, psk = "", psk_id = ""):
   a. psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id, suite_id)
   b. info_hash = LabeledExtract("", "info_hash", info, suite_id)
   c. ks_context = concat(mode, psk_id_hash, info_hash)
   d. secret = LabeledExtract(shared_secret, "secret", ks_context, suite_id)  [NOTE: see below]
   e. key = LabeledExpand(secret, "key", ks_context, 32, suite_id)       // Nk = 32 for AES-256
   f. base_nonce = LabeledExpand(secret, "base_nonce", ks_context, 12, suite_id)  // Nn = 12
3. ct = AES-256-GCM.Seal(key, base_nonce, aad, plaintext)
4. Return { enc, ciphertext: ct.ciphertext, iv: ct.iv, tag: ct.tag }
```

**NOTE on step 2d:** RFC 9180 Section 5.1 Key Schedule actually uses:
- `psk_id_hash = LabeledExtract("", "psk_id_hash", "", suite_id)` (empty psk_id for Base mode)
- `info_hash = LabeledExtract("", "info_hash", info, suite_id)`
- `ks_context = concat(I2OSP(mode, 1), psk_id_hash, info_hash)`
- `secret = LabeledExtract(shared_secret, "secret", default_psk, suite_id)` where default_psk = "" for Base mode

This will be verified exactly against RFC 9180 Appendix A test vectors at Gate 4.

### OpenBase(kem, enc, skR, info, aad, ciphertext)

```
1. shared_secret = kem.decapsulate(enc, skR)
2. Same key schedule as SealBase → key, base_nonce
3. plaintext = AES-256-GCM.Open(key, base_nonce, aad, ciphertext)
4. Return plaintext
```

**suite_id:** `concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2))`
- For DHKEM-X25519: `"HPKE" || 0x0020 || 0x0001 || 0x0002`
- For Hybrid KEM: custom ID (not in RFC 9180 — will use a private-use value)

**Single-shot only.** We wrap one DEK per call. The AEAD nonce sequence counter stays at 0, so `base_nonce` is used directly. No `ComputeNonce` or sequence increment logic.

---

## 7. Public API

**File:** `src/key-wrap.ts`

### Types

```typescript
interface MasterKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  kemId: string;
}

interface WrappedKey {
  enc: Uint8Array;         // KEM encapsulation (32 or 1120 bytes)
  ciphertext: Uint8Array;  // AES-256-GCM encrypted DEK
  iv: Uint8Array;          // 12 bytes (base_nonce from HPKE key schedule)
  tag: Uint8Array;         // 16 bytes (GCM auth tag)
  kemId: string;           // which KEM was used
}
```

### Functions

```typescript
/**
 * Generate a master keypair for key wrapping.
 * Default KEM: Hybrid-X25519-MLKEM768.
 */
generateMasterKeyPair(kem?: Kem): Promise<MasterKeyPair>

/**
 * Wrap a DEK under a master public key using HPKE Base mode.
 * The DEK must be exactly 32 bytes (AES-256 key).
 * Default KEM: Hybrid-X25519-MLKEM768.
 */
wrapKey(
  dek: Uint8Array,
  masterPublicKey: Uint8Array,
  options?: { kem?: Kem; info?: Uint8Array }
): Promise<WrappedKey>

/**
 * Unwrap a DEK using the master private key.
 * Throws AuthenticationError if the tag doesn't verify.
 * Throws DecapsulationError if KEM decapsulation fails.
 */
unwrapKey(
  wrapped: WrappedKey,
  masterPrivateKey: Uint8Array,
  options?: { kem?: Kem; info?: Uint8Array }
): Promise<Uint8Array>
```

### Input validation

- `dek` must be exactly 32 bytes (AES-256 key size) — throw `InvalidInputError` otherwise
- `masterPublicKey` must match the KEM's expected public key size
- `wrapped.kemId` must match the KEM being used to unwrap — throw `InvalidInputError` on mismatch
- `info` defaults to `new Uint8Array(0)` if omitted

### Default KEM

The default KEM is `Hybrid-X25519-MLKEM768`. To use classical-only:

```typescript
import { DHKEM_X25519 } from 'eternis-crypto';
const wrapped = await wrapKey(dek, masterPk, { kem: DHKEM_X25519 });
```

---

## 8. Error Classes

Added to existing `src/errors.ts`:

```typescript
class DecapsulationError extends EternisCryptoError {
  constructor(message: string) { super(message); this.name = 'DecapsulationError'; }
}

class KeyWrappingError extends EternisCryptoError {
  constructor(message: string) { super(message); this.name = 'KeyWrappingError'; }
}
```

The existing `AuthenticationError` is reused for GCM tag failures during unwrap.

---

## 9. Dependencies

### New (for hybrid KEM only)

| Package | Version | Purpose | Audit status |
|---------|---------|---------|-------------|
| `@noble/post-quantum` | latest | ML-KEM-768 Encaps/Decaps | Audited, Paul Miller |
| `@noble/hashes` | latest | SHA3-256 for X-Wing combiner | Audited, Paul Miller |

### Unchanged

- Web Crypto API (`crypto.subtle`) — X25519, HMAC-SHA-256, AES-256-GCM
- Zero other runtime deps

### Dev dependencies (unchanged)

- Vitest 2.0, TypeScript 5.4, ESLint 8

---

## 10. Test Strategy

### Test vectors (external validation)

| Source | What | Gate |
|--------|------|------|
| RFC 9180 Appendix A | HKDF LabeledExtract/LabeledExpand values | Gate 1 |
| RFC 9180 Appendix A | DHKEM(X25519, HKDF-SHA256) encapsulate/decapsulate | Gate 2 |
| X-Wing paper (Barbosa et al. 2024) | Hybrid KEM combiner output | Gate 3 |
| RFC 9180 Appendix A | HPKE Base mode SealBase/OpenBase | Gate 4 |

### Unit tests

| File | Coverage |
|------|----------|
| `hkdf.test.ts` | extract, expand, labeledExtract, labeledExpand, edge cases |
| `dhkem-x25519.test.ts` | Round-trip, vector validation, wrong-key rejection |
| `hybrid-kem.test.ts` | Round-trip, vector validation, combiner correctness, key size checks |
| `hpke.test.ts` | SealBase/OpenBase round-trip, vector validation, wrong-key → AuthenticationError |
| `key-wrap.test.ts` | wrapKey/unwrapKey round-trip (both KEMs), wrong-key, kemId mismatch, DEK size validation |
| `public-api.test.ts` | Updated to include all new exports |

### Test patterns (same as v0.1.0)

- Vitest `describe` + `it` blocks
- `Uint8Array` comparison via `Array.from()`
- Hex helper utilities for test vectors
- Test-only internal exports prefixed with `_`

---

## 11. Audit Gates

No gate passes without vector validation. If any vector doesn't match, stop and research.

### Gate 1 — HKDF
- All RFC 9180 Appendix A HKDF intermediate values reproduced exactly
- LabeledExtract and LabeledExpand produce correct outputs for the test suite

### Gate 2 — DHKEM-X25519
- RFC 9180 Appendix A DHKEM(X25519, HKDF-SHA256) test vectors pass
- Round-trip: encapsulate → decapsulate produces identical shared secret
- Wrong private key → different shared secret (no silent failure)

### Gate 3 — Hybrid KEM
- X-Wing paper test vectors: combiner output matches published values
- Round-trip: encapsulate → decapsulate produces identical shared secret
- Key size assertions: pk = 1216 bytes, sk = 2464 bytes, enc = 1120 bytes, ss = 32 bytes
- Wrong private key → different shared secret

### Gate 4 — HPKE Base Mode
- RFC 9180 Appendix A Base mode test vectors pass (with DHKEM-X25519 suite)
- SealBase → OpenBase round-trip with both KEMs
- Wrong key → AuthenticationError
- AAD mismatch → AuthenticationError

### Gate 5 — Public API
- wrapKey → unwrapKey round-trip with hybrid KEM (default)
- wrapKey → unwrapKey round-trip with DHKEM-X25519
- Wrong master private key → error
- DEK not 32 bytes → InvalidInputError
- kemId mismatch → InvalidInputError
- Export surface: exactly the expected symbols, no internal leaks

---

## 12. Non-Goals (explicit exclusions)

- **HPKE PSK, Auth, or AuthPSK modes** — not needed for DEK wrapping
- **Multi-message AEAD sequence** — single-shot only, no nonce sequence
- **Key serialization format** — out of scope, handled by the application layer
- **Key rotation** — future primitive, will use wrapKey/unwrapKey as building block
- **Key splitting** — independent primitive, operates on raw key bytes
- **ML-KEM standalone KEM** — no use case without classical fallback
- **Streaming encryption** — already handled by AES-256-GCM chunk layer

---

## 13. References

| Ref | Document |
|-----|----------|
| RFC 9180 | Hybrid Public Key Encryption (Barnes et al., 2022) |
| FIPS 203 | ML-KEM Standard (NIST, 2024) |
| SP 800-227 | Recommendations for KEMs (NIST, 2025) |
| X-Wing | Barbosa et al., "The Hybrid KEM You've Been Looking For" (2024) |
| RFC 5869 | HKDF (Krawczyk & Eronen, 2010) |
| RFC 7748 | Elliptic Curves for Security — X25519 (Langley et al., 2016) |
| Giacon 2018 | KEM Combiners (PKC 2018) |
| Alwen 2021 | Analysing the HPKE Standard (EUROCRYPT 2021) |
| PreVeil 2024 | Security Whitepaper v1.6 (deployed precedent) |

---

## 14. Open Questions (resolved during brainstorm)

| Question | Resolution |
|----------|-----------|
| Bespoke ECIES vs HPKE-aligned? | HPKE-aligned (RFC 9180) — formal proofs, standard recipe |
| Post-quantum deferred or day one? | Day one — harvest-now-decrypt-later threat model |
| X-Wing only vs pluggable KEM? | Pluggable KEM, hybrid default — X-Wing not yet an RFC |
| Zero deps vs noble dependency? | Take `@noble/post-quantum` + `@noble/hashes` — audited, necessary for ML-KEM |
| Monolithic vs layered modules? | Layered (KEM/KDF/AEAD) — matches RFC 9180 architecture |
| Audit approach? | Same as v0.1.0: 5 gates, vector validation, no improvisation |
