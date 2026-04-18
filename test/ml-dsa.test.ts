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
