import { describe, expect, it } from 'vitest';
import { generateShares, reconstructSecret } from '../src/sss/shamir.js';
import { bytesToBigInt, bigIntToBytes } from '../src/sss/field.js';

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
    // Note: 0xff*32 = 2^256-1 > P = 2^256-189, so use 0xfe which is within the field.
    const secret = new Uint8Array(32).fill(0xfe);
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
