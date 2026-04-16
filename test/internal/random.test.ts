import { describe, expect, it } from 'vitest';
import { randomBytes } from '../../src/internal/random.js';

describe('randomBytes', () => {
  it('returns Uint8Array of requested length', () => {
    const b = randomBytes(12);
    expect(b).toBeInstanceOf(Uint8Array);
    expect(b.length).toBe(12);
  });

  it('returns different bytes on successive calls (CSPRNG output)', () => {
    const a = randomBytes(12);
    const b = randomBytes(12);
    const equal = a.every((v, i) => v === b[i]);
    expect(equal).toBe(false);
  });

  it('length 0 returns empty Uint8Array', () => {
    const b = randomBytes(0);
    expect(b.length).toBe(0);
  });

  it('rejects negative length', () => {
    expect(() => randomBytes(-1)).toThrow();
  });

  it('rejects non-integer length', () => {
    expect(() => randomBytes(1.5)).toThrow();
  });
});
