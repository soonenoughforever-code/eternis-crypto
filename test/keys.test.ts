import { describe, expect, it } from 'vitest';
import { generateKey, KeyHandle, _importRawKey } from '../src/keys.js';

describe('generateKey', () => {
  it('returns a KeyHandle with algorithm AES-256-GCM', async () => {
    const k = await generateKey();
    expect(k).toBeInstanceOf(KeyHandle);
    expect(k.algorithm).toBe('AES-256-GCM');
  });

  it('initial invocations is 0', async () => {
    const k = await generateKey();
    expect(k.invocations).toBe(0);
  });

  it('maxInvocations is 2^32', async () => {
    const k = await generateKey();
    expect(k.maxInvocations).toBe(4_294_967_296);
  });

  it('generates distinct handles across calls', async () => {
    const a = await generateKey();
    const b = await generateKey();
    expect(a).not.toBe(b);
  });
});

describe('_importRawKey', () => {
  it('imports a 32-byte key and returns a usable KeyHandle', async () => {
    const raw = new Uint8Array(32).fill(0x42);
    const k = await _importRawKey(raw);
    expect(k).toBeInstanceOf(KeyHandle);
    expect(k.algorithm).toBe('AES-256-GCM');
    expect(k.invocations).toBe(0);
  });

  it('rejects 16-byte key', async () => {
    await expect(_importRawKey(new Uint8Array(16))).rejects.toThrow();
  });

  it('rejects 33-byte key', async () => {
    await expect(_importRawKey(new Uint8Array(33))).rejects.toThrow();
  });
});
