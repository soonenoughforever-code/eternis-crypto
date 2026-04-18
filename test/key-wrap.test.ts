import { describe, expect, it } from 'vitest';
import { wrapKey, unwrapKey, generateMasterKeyPair } from '../src/key-wrap.js';
import { DHKEM_X25519 } from '../src/kem/dhkem-x25519.js';
import { AuthenticationError, InvalidInputError } from '../src/errors.js';

describe('generateMasterKeyPair', () => {
  it('defaults to hybrid KEM', async () => {
    const kp = await generateMasterKeyPair();
    expect(kp.kemId).toBe('Hybrid-X25519-MLKEM768');
    expect(kp.publicKey.length).toBe(1216);
    expect(kp.privateKey.length).toBe(2464);
  });

  it('accepts DHKEM-X25519', async () => {
    const kp = await generateMasterKeyPair(DHKEM_X25519);
    expect(kp.kemId).toBe('DHKEM-X25519-HKDF-SHA256');
    expect(kp.publicKey.length).toBe(32);
    expect(kp.privateKey.length).toBe(64);
  });
});

describe('wrapKey + unwrapKey round-trip (hybrid default)', () => {
  it('wraps and unwraps a 32-byte DEK', async () => {
    const kp = await generateMasterKeyPair();
    const dek = globalThis.crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapKey(dek, kp.publicKey);

    expect(wrapped.kemId).toBe('Hybrid-X25519-MLKEM768');
    expect(wrapped.enc.length).toBe(1120);
    expect(wrapped.ciphertext.length).toBe(32);
    expect(wrapped.iv.length).toBe(12);
    expect(wrapped.tag.length).toBe(16);

    const unwrapped = await unwrapKey(wrapped, kp.privateKey);
    expect(Array.from(unwrapped)).toEqual(Array.from(dek));
  });
});

describe('wrapKey + unwrapKey round-trip (DHKEM-X25519)', () => {
  it('wraps and unwraps a 32-byte DEK', async () => {
    const kp = await generateMasterKeyPair(DHKEM_X25519);
    const dek = globalThis.crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapKey(dek, kp.publicKey, { kem: DHKEM_X25519 });

    expect(wrapped.kemId).toBe('DHKEM-X25519-HKDF-SHA256');
    expect(wrapped.enc.length).toBe(32);

    const unwrapped = await unwrapKey(wrapped, kp.privateKey, { kem: DHKEM_X25519 });
    expect(Array.from(unwrapped)).toEqual(Array.from(dek));
  });
});

describe('wrapKey + unwrapKey error cases', () => {
  it('wrong master private key throws AuthenticationError', async () => {
    const kp1 = await generateMasterKeyPair();
    const kp2 = await generateMasterKeyPair();
    const dek = new Uint8Array(32).fill(0x42);

    const wrapped = await wrapKey(dek, kp1.publicKey);

    await expect(unwrapKey(wrapped, kp2.privateKey)).rejects.toThrow(AuthenticationError);
  });

  it('DEK not 32 bytes throws InvalidInputError', async () => {
    const kp = await generateMasterKeyPair();

    await expect(wrapKey(new Uint8Array(16), kp.publicKey)).rejects.toThrow(InvalidInputError);
    await expect(wrapKey(new Uint8Array(33), kp.publicKey)).rejects.toThrow(InvalidInputError);
    await expect(wrapKey(new Uint8Array(0), kp.publicKey)).rejects.toThrow(InvalidInputError);
  });

  it('kemId mismatch throws InvalidInputError', async () => {
    const kp = await generateMasterKeyPair();
    const dek = new Uint8Array(32).fill(0x42);

    const wrapped = await wrapKey(dek, kp.publicKey);

    await expect(
      unwrapKey(wrapped, kp.privateKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('wrong-size masterPublicKey throws InvalidInputError', async () => {
    const dek = new Uint8Array(32).fill(0x42);
    await expect(wrapKey(dek, new Uint8Array(16))).rejects.toThrow(InvalidInputError);
  });

  it('tampered enc throws AuthenticationError', async () => {
    const kp = await generateMasterKeyPair(DHKEM_X25519);
    const dek = new Uint8Array(32).fill(0x42);
    const wrapped = await wrapKey(dek, kp.publicKey, { kem: DHKEM_X25519 });
    const tamperedEnc = new Uint8Array(wrapped.enc);
    tamperedEnc.set([tamperedEnc[0]! ^ 0x01], 0);
    await expect(
      unwrapKey({ ...wrapped, enc: tamperedEnc }, kp.privateKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('tampered ciphertext throws AuthenticationError', async () => {
    const kp = await generateMasterKeyPair(DHKEM_X25519);
    const dek = new Uint8Array(32).fill(0x42);
    const wrapped = await wrapKey(dek, kp.publicKey, { kem: DHKEM_X25519 });
    const tamperedCt = new Uint8Array(wrapped.ciphertext);
    tamperedCt.set([tamperedCt[0]! ^ 0x01], 0);
    await expect(
      unwrapKey({ ...wrapped, ciphertext: tamperedCt }, kp.privateKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(AuthenticationError);
  });
});

describe('wrapKey + unwrapKey with info parameter', () => {
  it('same info produces same DEK', async () => {
    const kp = await generateMasterKeyPair(DHKEM_X25519);
    const dek = new Uint8Array(32).fill(0xab);
    const info = new TextEncoder().encode('sample-id-001');

    const wrapped = await wrapKey(dek, kp.publicKey, { kem: DHKEM_X25519, info });
    const unwrapped = await unwrapKey(wrapped, kp.privateKey, { kem: DHKEM_X25519, info });

    expect(Array.from(unwrapped)).toEqual(Array.from(dek));
  });

  it('different info fails to unwrap', async () => {
    const kp = await generateMasterKeyPair(DHKEM_X25519);
    const dek = new Uint8Array(32).fill(0xab);

    const wrapped = await wrapKey(dek, kp.publicKey, {
      kem: DHKEM_X25519,
      info: new TextEncoder().encode('info-a'),
    });

    await expect(
      unwrapKey(wrapped, kp.privateKey, {
        kem: DHKEM_X25519,
        info: new TextEncoder().encode('info-b'),
      }),
    ).rejects.toThrow(AuthenticationError);
  });
});
