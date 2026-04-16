import { describe, expect, it } from 'vitest';
import { encryptChunk, decryptChunk } from '../src/aes-gcm.js';
import { generateKey } from '../src/keys.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

describe('encryptChunk / decryptChunk — round-trip', () => {
  it('round-trips a short plaintext with empty AAD', async () => {
    const key = await generateKey();
    const pt = enc.encode('hello world');
    const aad = new Uint8Array(0);
    const ct = await encryptChunk(key, pt, aad);
    const recovered = await decryptChunk(key, ct, aad);
    expect(dec.decode(recovered)).toBe('hello world');
  });

  it('round-trips with non-empty AAD', async () => {
    const key = await generateKey();
    const pt = enc.encode('payload');
    const aad = enc.encode('context-label-v1');
    const ct = await encryptChunk(key, pt, aad);
    const recovered = await decryptChunk(key, ct, aad);
    expect(dec.decode(recovered)).toBe('payload');
  });

  it('produces a 12-byte IV and 16-byte tag', async () => {
    const key = await generateKey();
    const ct = await encryptChunk(key, enc.encode('x'), new Uint8Array(0));
    expect(ct.iv.length).toBe(12);
    expect(ct.tag.length).toBe(16);
  });

  it('ciphertext length equals plaintext length', async () => {
    const key = await generateKey();
    const pt = enc.encode('exactly sixteen!'); // 16 bytes
    const ct = await encryptChunk(key, pt, new Uint8Array(0));
    expect(ct.ciphertext.length).toBe(pt.length);
  });

  it('produces different IV and ciphertext for same plaintext (random IV)', async () => {
    const key = await generateKey();
    const pt = enc.encode('same input');
    const aad = new Uint8Array(0);
    const a = await encryptChunk(key, pt, aad);
    const b = await encryptChunk(key, pt, aad);
    expect(Array.from(a.iv)).not.toEqual(Array.from(b.iv));
    expect(Array.from(a.ciphertext)).not.toEqual(Array.from(b.ciphertext));
  });

  it('encryptChunk increments the invocation counter by 1', async () => {
    const key = await generateKey();
    expect(key.invocations).toBe(0);
    await encryptChunk(key, enc.encode('a'), new Uint8Array(0));
    expect(key.invocations).toBe(1);
    await encryptChunk(key, enc.encode('b'), new Uint8Array(0));
    expect(key.invocations).toBe(2);
  });

  it('decryptChunk does NOT increment the invocation counter', async () => {
    const key = await generateKey();
    const ct = await encryptChunk(key, enc.encode('x'), new Uint8Array(0));
    expect(key.invocations).toBe(1);
    await decryptChunk(key, ct, new Uint8Array(0));
    expect(key.invocations).toBe(1);
  });
});
