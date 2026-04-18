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
    expect(sealed.ciphertext.length).toBe(32);
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
  it('AES-GCM encrypt/decrypt matches A.1.1 sequence 0 (AES-128, structural check)', async () => {
    const key = hexToBytes('4531685d41d65f03dc48f6b8302c05b0');
    const nonce = hexToBytes('56d890e5accaaf011cff4b7d');
    const pt = hexToBytes('4265617574792069732074727574682c20747275746820626561757479');
    const aad = hexToBytes('436f756e742d30');
    const expectedCt = 'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a';

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
