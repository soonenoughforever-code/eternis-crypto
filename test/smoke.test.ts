import { describe, expect, it } from 'vitest';

describe('smoke', () => {
  it('vitest is running', () => {
    expect(1 + 1).toBe(2);
  });

  it('Web Crypto API is available', () => {
    expect(globalThis.crypto).toBeDefined();
    expect(globalThis.crypto.subtle).toBeDefined();
    expect(typeof globalThis.crypto.getRandomValues).toBe('function');
  });

  it('Node version meets the >=22 engine requirement', () => {
    const majorStr = process.versions.node.split('.')[0] ?? '0';
    const major = parseInt(majorStr, 10);
    expect(major).toBeGreaterThanOrEqual(22);
  });
});
