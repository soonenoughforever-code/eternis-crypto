import { describe, expect, it } from 'vitest';
import { HYBRID_X25519_MLKEM768, _combiner } from '../src/kem/hybrid-kem.js';
import { hexToBytes } from './helpers/parse-rsp.js';
import { sha3_256 } from '@noble/hashes/sha3.js';

describe('Hybrid KEM properties', () => {
  it('has correct id', () => {
    expect(HYBRID_X25519_MLKEM768.id).toBe('Hybrid-X25519-MLKEM768');
  });

  it('has correct sizes', () => {
    expect(HYBRID_X25519_MLKEM768.publicKeySize).toBe(1216);   // ML-KEM pk 1184 + X25519 pk 32
    expect(HYBRID_X25519_MLKEM768.privateKeySize).toBe(2464);  // ML-KEM sk 2400 + X25519 sk 32 + X25519 pk 32
    expect(HYBRID_X25519_MLKEM768.encSize).toBe(1120);          // ML-KEM ct 1088 + X25519 ct 32
    expect(HYBRID_X25519_MLKEM768.sharedSecretSize).toBe(32);
  });
});

describe('Hybrid KEM generateKeyPair', () => {
  it('produces keys of correct sizes', async () => {
    const { publicKey, privateKey } = await HYBRID_X25519_MLKEM768.generateKeyPair();
    expect(publicKey.length).toBe(1216);
    expect(privateKey.length).toBe(2464);
  });
});

describe('Hybrid KEM X-Wing combiner', () => {
  it('produces SHA3-256 of XWingLabel || ss_M || ss_X || ct_X || pk_X', () => {
    // Known inputs — verify combiner matches manual SHA3-256 computation
    const ssM = new Uint8Array(32).fill(0xaa);
    const ssX = new Uint8Array(32).fill(0xbb);
    const ctX = new Uint8Array(32).fill(0xcc);
    const pkX = new Uint8Array(32).fill(0xdd);

    const result = _combiner(ssM, ssX, ctX, pkX);

    // XWingLabel = hex 5c2e2f2f5e5c
    const label = hexToBytes('5c2e2f2f5e5c');
    const input = new Uint8Array(6 + 32 + 32 + 32 + 32);
    input.set(label, 0);
    input.set(ssM, 6);
    input.set(ssX, 38);
    input.set(ctX, 70);
    input.set(pkX, 102);
    const expected = sha3_256(input);

    expect(Array.from(result)).toEqual(Array.from(expected));
    expect(result.length).toBe(32);
  });
});

describe('Hybrid KEM round-trip', () => {
  it('encapsulate then decapsulate produces matching shared secret', async () => {
    const { publicKey, privateKey } = await HYBRID_X25519_MLKEM768.generateKeyPair();
    const { sharedSecret: ss1, enc } = await HYBRID_X25519_MLKEM768.encapsulate(publicKey);

    expect(enc.length).toBe(1120);
    expect(ss1.length).toBe(32);

    const ss2 = await HYBRID_X25519_MLKEM768.decapsulate(enc, privateKey);
    expect(Array.from(ss2)).toEqual(Array.from(ss1));
  });

  it('wrong private key produces different shared secret', async () => {
    const kp1 = await HYBRID_X25519_MLKEM768.generateKeyPair();
    const kp2 = await HYBRID_X25519_MLKEM768.generateKeyPair();

    const { sharedSecret: ss1, enc } = await HYBRID_X25519_MLKEM768.encapsulate(kp1.publicKey);
    const ss2 = await HYBRID_X25519_MLKEM768.decapsulate(enc, kp2.privateKey);

    expect(Array.from(ss2)).not.toEqual(Array.from(ss1));
  });

  it('multiple encapsulations produce different shared secrets', async () => {
    const { publicKey } = await HYBRID_X25519_MLKEM768.generateKeyPair();
    const r1 = await HYBRID_X25519_MLKEM768.encapsulate(publicKey);
    const r2 = await HYBRID_X25519_MLKEM768.encapsulate(publicKey);

    expect(Array.from(r1.enc)).not.toEqual(Array.from(r2.enc));
    expect(Array.from(r1.sharedSecret)).not.toEqual(Array.from(r2.sharedSecret));
  });
});
