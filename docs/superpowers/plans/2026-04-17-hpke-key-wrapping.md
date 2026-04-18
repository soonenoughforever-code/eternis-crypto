### Task 5: HPKE Base Mode + Gate 4

**Files:**
- Create: `src/hpke.ts`
- Create: `test/hpke.test.ts`

**Test vectors:** RFC 9180 A.1.1 key schedule intermediate values (AES-128-GCM suite, Nk=16) for structural validation, cross-implementation comparison against @noble/hashes reference for AES-256-GCM suite, plus round-trip with both KEMs.

- [ ] **Step 1: Write the failing test**

Create `test/hpke.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import { sealBase, openBase, _keySchedule } from '../src/hpke.js';
import { DHKEM_X25519 } from '../src/kem/dhkem-x25519.js';
import { HYBRID_X25519_MLKEM768 } from '../src/kem/hybrid-kem.js';
import { refKeySchedule, buildRefSuiteId } from './reference-keyschedule.js';
import { hexToBytes, bytesToHex } from './helpers/parse-rsp.js';
import { concat, i2osp } from '../src/hkdf.js';
import { AuthenticationError } from '../src/errors.js';

describe('HPKE key schedule (RFC 9180 A.1.1 vectors — AES-128-GCM suite)', () => {
  // Suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
  // suite_id = "HPKE" || 0x0020 || 0x0001 || 0x0001
  const suiteId = (() => {
    const prefix = new TextEncoder().encode('HPKE');
    return concat(prefix, i2osp(0x0020, 2), i2osp(0x0001, 2), i2osp(0x0001, 2));
  })();

  const sharedSecret = hexToBytes('fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc');
  const info = hexToBytes('4f6465206f6e2061204772656369616e2055726e');

  it('produces correct key and base_nonce for AES-128-GCM (Nk=16, Nn=12)', async () => {
    const { key, baseNonce } = await _keySchedule(0x00, sharedSecret, info, suiteId, 16, 12);
    expect(bytesToHex(key)).toBe('4531685d41d65f03dc48f6b8302c05b0');
    expect(bytesToHex(baseNonce)).toBe('56d890e5accaaf011cff4b7d');
  });
});

describe('Cross-implementation validation: AES-256-GCM key schedule', () => {
  // Uses the @noble/hashes reference (validated against A.1.1 in Task 0)
  // to cross-check our Web Crypto key schedule for the AES-256-GCM suite.
  const sharedSecret = hexToBytes('fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc');
  const info = hexToBytes('4f6465206f6e2061204772656369616e2055726e');

  // Our production suite: DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM
  const suiteId = (() => {
    const prefix = new TextEncoder().encode('HPKE');
    return concat(prefix, i2osp(0x0020, 2), i2osp(0x0001, 2), i2osp(0x0002, 2));
  })();

  it('key matches @noble/hashes reference (Nk=32)', async () => {
    const refSuiteId = buildRefSuiteId(0x0020, 0x0001, 0x0002);
    const ref = refKeySchedule(0x00, sharedSecret, info, refSuiteId, 32, 12);
    const ours = await _keySchedule(0x00, sharedSecret, info, suiteId, 32, 12);
    expect(Array.from(ours.key)).toEqual(Array.from(ref.key));
  });

  it('base_nonce matches @noble/hashes reference (Nn=12)', async () => {
    const refSuiteId = buildRefSuiteId(0x0020, 0x0001, 0x0002);
    const ref = refKeySchedule(0x00, sharedSecret, info, refSuiteId, 32, 12);
    const ours = await _keySchedule(0x00, sharedSecret, info, suiteId, 32, 12);
    expect(Array.from(ours.baseNonce)).toEqual(Array.from(ref.baseNonce));
  });
});

describe('HPKE SealBase + OpenBase round-trip (DHKEM-X25519, AES-256-GCM)', () => {
  it('encrypts and decrypts a 32-byte DEK', async () => {
    const { publicKey, privateKey } = await DHKEM_X25519.generateKeyPair();
    const dek = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const info = new Uint8Array(0);
    const aad = new TextEncoder().encode('eternis-v0.2');

    const sealed = await sealBase(DHKEM_X25519, publicKey, info, aad, dek);

    expect(sealed.enc.length).toBe(32);
    expect(sealed.ciphertext.length).toBe(32); // same as plaintext
    expect(sealed.iv.length).toBe(12);
    expect(sealed.tag.length).toBe(16);

    const plaintext = await openBase(DHKEM_X25519, sealed.enc, privateKey, info, aad, {
      ciphertext: sealed.ciphertext,
      iv: sealed.iv,
      tag: sealed.tag,
    });

    expect(Array.from(plaintext)).toEqual(Array.from(dek));
  });

  it('wrong private key throws AuthenticationError', async () => {
    const kp1 = await DHKEM_X25519.generateKeyPair();
    const kp2 = await DHKEM_X25519.generateKeyPair();
    const dek = new Uint8Array(32).fill(0x42);
    const info = new Uint8Array(0);
    const aad = new Uint8Array(0);

    const sealed = await sealBase(DHKEM_X25519, kp1.publicKey, info, aad, dek);

    await expect(
      openBase(DHKEM_X25519, sealed.enc, kp2.privateKey, info, aad, {
        ciphertext: sealed.ciphertext,
        iv: sealed.iv,
        tag: sealed.tag,
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('tampered AAD throws AuthenticationError', async () => {
    const { publicKey, privateKey } = await DHKEM_X25519.generateKeyPair();
    const dek = new Uint8Array(32).fill(0x42);
    const info = new Uint8Array(0);
    const aad = new TextEncoder().encode('original');

    const sealed = await sealBase(DHKEM_X25519, publicKey, info, aad, dek);

    await expect(
      openBase(DHKEM_X25519, sealed.enc, privateKey, info, new TextEncoder().encode('tampered'), {
        ciphertext: sealed.ciphertext,
        iv: sealed.iv,
        tag: sealed.tag,
      }),
    ).rejects.toThrow(AuthenticationError);
  });
});

describe('HPKE SealBase + OpenBase round-trip (Hybrid KEM, AES-256-GCM)', () => {
  it('encrypts and decrypts a 32-byte DEK', async () => {
    const { publicKey, privateKey } = await HYBRID_X25519_MLKEM768.generateKeyPair();
    const dek = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const info = new Uint8Array(0);
    const aad = new TextEncoder().encode('eternis-hybrid');

    const sealed = await sealBase(HYBRID_X25519_MLKEM768, publicKey, info, aad, dek);

    expect(sealed.enc.length).toBe(1120);

    const plaintext = await openBase(HYBRID_X25519_MLKEM768, sealed.enc, privateKey, info, aad, {
      ciphertext: sealed.ciphertext,
      iv: sealed.iv,
      tag: sealed.tag,
    });

    expect(Array.from(plaintext)).toEqual(Array.from(dek));
  });

  it('wrong private key throws AuthenticationError', async () => {
    const kp1 = await HYBRID_X25519_MLKEM768.generateKeyPair();
    const kp2 = await HYBRID_X25519_MLKEM768.generateKeyPair();
    const dek = new Uint8Array(32).fill(0x42);

    const sealed = await sealBase(HYBRID_X25519_MLKEM768, kp1.publicKey, new Uint8Array(0), new Uint8Array(0), dek);

    await expect(
      openBase(HYBRID_X25519_MLKEM768, sealed.enc, kp2.privateKey, new Uint8Array(0), new Uint8Array(0), {
        ciphertext: sealed.ciphertext,
        iv: sealed.iv,
        tag: sealed.tag,
      }),
    ).rejects.toThrow(AuthenticationError);
  });
});

describe('HPKE SealBase + OpenBase with RFC 9180 A.1.1 encryption vector', () => {
  // Validate that when we know the key and nonce (derived from key schedule),
  // the AES-GCM encryption matches the RFC vector.
  // A.1.1 uses AES-128-GCM (key=16 bytes), but our production code uses AES-256-GCM.
  // This test directly verifies the AEAD portion using the A.1.1 key/nonce/pt/aad/ct.
  it('AES-GCM encrypt/decrypt matches A.1.1 sequence 0 (AES-128, structural check)', async () => {
    const key = hexToBytes('4531685d41d65f03dc48f6b8302c05b0');
    const nonce = hexToBytes('56d890e5accaaf011cff4b7d');
    const pt = hexToBytes('4265617574792069732074727574682c20747275746820626561757479');
    const aad = hexToBytes('436f756e742d30');
    const expectedCt = 'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a';

    // Encrypt with AES-128-GCM using Web Crypto directly
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      key as Uint8Array<ArrayBuffer>,
      { name: 'AES-GCM', length: 128 },
      false,
      ['encrypt'],
    );
    const combined = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce as Uint8Array<ArrayBuffer>, additionalData: aad as Uint8Array<ArrayBuffer>, tagLength: 128 },
        cryptoKey,
        pt as Uint8Array<ArrayBuffer>,
      ),
    );

    expect(bytesToHex(combined)).toBe(expectedCt);
  });
});
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npx vitest run test/hpke.test.ts
```

Expected: FAIL — `Cannot find module '../src/hpke.js'`

- [ ] **Step 3: Implement HPKE Base mode**

Create `src/hpke.ts`:

```typescript
import type { Kem } from './kem/kem.js';
import { labeledExtract, labeledExpand, concat, i2osp } from './hkdf.js';
import { AuthenticationError } from './errors.js';

const TAG_BYTES = 16;

/** Build the HPKE suite_id: "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2) */
function buildSuiteId(kemId: number, kdfId: number, aeadId: number): Uint8Array {
  const prefix = new TextEncoder().encode('HPKE');
  return concat(prefix, i2osp(kemId, 2), i2osp(kdfId, 2), i2osp(aeadId, 2));
}

// DHKEM(X25519, HKDF-SHA256) KEM ID
const KEM_ID_DHKEM_X25519 = 0x0020;
// Hybrid KEM — private-use KEM ID
const KEM_ID_HYBRID = 0xff01;
// HKDF-SHA256 KDF ID
const KDF_ID = 0x0001;
// AES-256-GCM AEAD ID
const AEAD_ID = 0x0002;

// AES-256-GCM parameters
const NK = 32; // key length
const NN = 12; // nonce length

function kemIdFromString(id: string): number {
  switch (id) {
    case 'DHKEM-X25519-HKDF-SHA256': return KEM_ID_DHKEM_X25519;
    case 'Hybrid-X25519-MLKEM768': return KEM_ID_HYBRID;
    default: throw new Error(`Unknown KEM id: ${id}`);
  }
}

/**
 * HPKE Key Schedule (RFC 9180 Section 5.1).
 * Exported with underscore prefix for test-only use — not in public API.
 *
 * @param mode - 0x00 for Base
 * @param suiteId - "HPKE" || kem_id || kdf_id || aead_id
 * @param nk - key length (32 for AES-256-GCM, 16 for AES-128-GCM in tests)
 * @param nn - nonce length (12)
 */
export async function _keySchedule(
  mode: number,
  sharedSecret: Uint8Array,
  info: Uint8Array,
  suiteId: Uint8Array,
  nk: number,
  nn: number,
): Promise<{ key: Uint8Array; baseNonce: Uint8Array }> {
  // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id="")
  const pskIdHash = await labeledExtract(new Uint8Array(0), 'psk_id_hash', new Uint8Array(0), suiteId);
  // info_hash = LabeledExtract("", "info_hash", info)
  const infoHash = await labeledExtract(new Uint8Array(0), 'info_hash', info, suiteId);
  // key_schedule_context = concat(I2OSP(mode, 1), psk_id_hash, info_hash)
  const ksContext = concat(new Uint8Array([mode]), pskIdHash, infoHash);
  // secret = LabeledExtract(shared_secret, "secret", psk="")
  const secret = await labeledExtract(sharedSecret, 'secret', new Uint8Array(0), suiteId);
  // key = LabeledExpand(secret, "key", ks_context, Nk)
  const key = await labeledExpand(secret, 'key', ksContext, nk, suiteId);
  // base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn)
  const baseNonce = await labeledExpand(secret, 'base_nonce', ksContext, nn, suiteId);

  return { key, baseNonce };
}

interface SealResult {
  enc: Uint8Array;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

/**
 * HPKE Base mode SealBase (RFC 9180 Section 5.1).
 * Single-shot: encrypts plaintext under pkR using the KEM shared secret.
 */
export async function sealBase(
  kem: Kem,
  pkR: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<SealResult> {
  const { sharedSecret, enc } = await kem.encapsulate(pkR);
  const suiteId = buildSuiteId(kemIdFromString(kem.id), KDF_ID, AEAD_ID);
  const { key, baseNonce } = await _keySchedule(0x00, sharedSecret, info, suiteId, NK, NN);

  // AES-256-GCM encrypt (single-shot, sequence number = 0, nonce = base_nonce)
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    key as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const combined = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: baseNonce as Uint8Array<ArrayBuffer>,
        additionalData: aad as Uint8Array<ArrayBuffer>,
        tagLength: 128,
      },
      cryptoKey,
      plaintext as Uint8Array<ArrayBuffer>,
    ),
  );

  const ciphertext = combined.slice(0, combined.length - TAG_BYTES);
  const tag = combined.slice(combined.length - TAG_BYTES);

  return { enc, ciphertext, iv: baseNonce, tag };
}

interface CiphertextParts {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

/**
 * HPKE Base mode OpenBase (RFC 9180 Section 5.1).
 * Single-shot: decrypts ciphertext using skR and the KEM shared secret.
 */
export async function openBase(
  kem: Kem,
  enc: Uint8Array,
  skR: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ct: CiphertextParts,
): Promise<Uint8Array> {
  const sharedSecret = await kem.decapsulate(enc, skR);
  const suiteId = buildSuiteId(kemIdFromString(kem.id), KDF_ID, AEAD_ID);
  const { key, baseNonce } = await _keySchedule(0x00, sharedSecret, info, suiteId, NK, NN);

  // AES-256-GCM decrypt
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    key as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );

  const combined = new Uint8Array(ct.ciphertext.length + ct.tag.length);
  combined.set(ct.ciphertext, 0);
  combined.set(ct.tag, ct.ciphertext.length);

  try {
    return new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: baseNonce as Uint8Array<ArrayBuffer>,
          additionalData: aad as Uint8Array<ArrayBuffer>,
          tagLength: 128,
        },
        cryptoKey,
        combined,
      ),
    );
  } catch (cause) {
    throw new AuthenticationError(
      'HPKE open failed: tag mismatch (wrong key, wrong AAD, or tampered ciphertext)',
      { cause },
    );
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run test/hpke.test.ts
```

Expected: ALL PASS (9 tests). The key schedule MUST reproduce the A.1.1 key and base_nonce exactly. The cross-implementation test MUST show our Web Crypto key schedule matches the @noble/hashes reference for the AES-256-GCM suite. The AES-GCM structural check MUST match the A.1.1 ciphertext. Round-trip tests with both KEMs must succeed. If any test fails, **STOP** and debug.

- [ ] **Step 5: Typecheck**

```bash
npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 6: Commit — Gate 4 passes**

```bash
git add src/hpke.ts test/hpke.test.ts
git commit -m "feat: add HPKE Base mode SealBase/OpenBase with AES-256-GCM (Gate 4)

Key schedule validated against RFC 9180 Appendix A.1.1 intermediate
values. AES-GCM structural check matches A.1.1 encryption vector.
Round-trip tests pass with both DHKEM-X25519 and Hybrid KEM."
```

---
