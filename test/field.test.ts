import { describe, expect, it } from 'vitest';
import {
  P,
  mod,
  add,
  sub,
  mul,
  inv,
  pow,
  bytesToBigInt,
  bigIntToBytes,
} from '../src/sss/field.js';

describe('field constants', () => {
  it('P equals 2^256 - 189', () => {
    expect(P).toBe(2n ** 256n - 189n);
  });
});

describe('mod', () => {
  it('reduces positive values into [0, P)', () => {
    expect(mod(0n)).toBe(0n);
    expect(mod(1n)).toBe(1n);
    expect(mod(P)).toBe(0n);
    expect(mod(P + 1n)).toBe(1n);
  });

  it('handles negative values', () => {
    expect(mod(-1n)).toBe(P - 1n);
    expect(mod(-P)).toBe(0n);
  });
});

describe('add', () => {
  it('adds two values mod P', () => {
    expect(add(1n, 2n)).toBe(3n);
  });

  it('wraps on overflow', () => {
    expect(add(P - 1n, 1n)).toBe(0n);
    expect(add(P - 1n, 2n)).toBe(1n);
  });

  it('identity: add(a, 0) === a', () => {
    const a = 123456789n;
    expect(add(a, 0n)).toBe(a);
  });
});

describe('sub', () => {
  it('subtracts two values mod P', () => {
    expect(sub(5n, 3n)).toBe(2n);
  });

  it('wraps on underflow (never negative)', () => {
    expect(sub(0n, 1n)).toBe(P - 1n);
    expect(sub(1n, 3n)).toBe(P - 2n);
  });
});

describe('mul', () => {
  it('multiplies two values mod P', () => {
    expect(mul(3n, 7n)).toBe(21n);
  });

  it('identity: mul(a, 1) === a', () => {
    const a = 999999999n;
    expect(mul(a, 1n)).toBe(a);
  });

  it('zero: mul(a, 0) === 0', () => {
    expect(mul(12345n, 0n)).toBe(0n);
  });
});

describe('inv', () => {
  it('inv(a) * a === 1 mod P', () => {
    const a = 42n;
    expect(mul(a, inv(a))).toBe(1n);
  });

  it('inv(1) === 1', () => {
    expect(inv(1n)).toBe(1n);
  });

  it('inv(P - 1) * (P - 1) === 1 mod P', () => {
    const a = P - 1n;
    expect(mul(a, inv(a))).toBe(1n);
  });

  it('inv of random large value', () => {
    const a = 0xdeadbeefcafebabe1234567890abcdefn;
    expect(mul(a, inv(a))).toBe(1n);
  });

  it('throws on zero', () => {
    expect(() => inv(0n)).toThrow('Cannot compute inverse of zero');
  });
});

describe('pow', () => {
  it('computes modular exponentiation', () => {
    expect(pow(2n, 10n)).toBe(1024n);
  });

  it('pow(a, 0) === 1', () => {
    expect(pow(12345n, 0n)).toBe(1n);
  });

  it('pow(a, 1) === a mod P', () => {
    expect(pow(42n, 1n)).toBe(42n);
  });

  it('Fermat witness: pow(a, P - 1) === 1 for a != 0', () => {
    expect(pow(7n, P - 1n)).toBe(1n);
  });
});

describe('bytesToBigInt / bigIntToBytes', () => {
  it('round-trips a 32-byte value', () => {
    const bytes = new Uint8Array(32);
    bytes[0] = 0xff;
    bytes[31] = 0x01;
    const n = bytesToBigInt(bytes);
    const out = bigIntToBytes(n);
    expect(Array.from(out)).toEqual(Array.from(bytes));
  });

  it('round-trips all zeros', () => {
    const bytes = new Uint8Array(32);
    const n = bytesToBigInt(bytes);
    expect(n).toBe(0n);
    const out = bigIntToBytes(n);
    expect(Array.from(out)).toEqual(Array.from(bytes));
  });

  it('round-trips all 0xff', () => {
    const bytes = new Uint8Array(32).fill(0xff);
    const n = bytesToBigInt(bytes);
    expect(n).toBe(2n ** 256n - 1n);
    const out = bigIntToBytes(n);
    expect(Array.from(out)).toEqual(Array.from(bytes));
  });

  it('bigIntToBytes zero-pads to 32 bytes', () => {
    const out = bigIntToBytes(1n);
    expect(out.length).toBe(32);
    expect(out[31]).toBe(1);
    expect(out[0]).toBe(0);
  });
});
