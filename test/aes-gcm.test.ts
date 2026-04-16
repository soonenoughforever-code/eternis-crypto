import { describe, expect, it } from 'vitest';
import { encryptChunk, decryptChunk } from '../src/aes-gcm.js';
import { generateKey, _internals } from '../src/keys.js';
import { AuthenticationError } from '../src/errors.js';
import { InvalidInputError } from '../src/errors.js';
import { KeyExhaustedError } from '../src/errors.js';

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

describe('encryptChunk / decryptChunk — authentication failures', () => {
  it('rejects wrong AAD on decrypt', async () => {
    const key = await generateKey();
    const ct = await encryptChunk(key, enc.encode('payload'), enc.encode('aad-a'));
    await expect(decryptChunk(key, ct, enc.encode('aad-b'))).rejects.toThrow(AuthenticationError);
  });

  it('rejects tampered ciphertext byte', async () => {
    const key = await generateKey();
    const ct = await encryptChunk(key, enc.encode('important message'), new Uint8Array(0));
    const tamperedCiphertext = new Uint8Array(ct.ciphertext);
    tamperedCiphertext[0] = (tamperedCiphertext[0] ?? 0) ^ 0x01;
    const tampered = { iv: ct.iv, ciphertext: tamperedCiphertext, tag: ct.tag };
    await expect(decryptChunk(key, tampered, new Uint8Array(0))).rejects.toThrow(AuthenticationError);
  });

  it('rejects tampered tag byte', async () => {
    const key = await generateKey();
    const ct = await encryptChunk(key, enc.encode('important message'), new Uint8Array(0));
    const tamperedTag = new Uint8Array(ct.tag);
    tamperedTag[0] = (tamperedTag[0] ?? 0) ^ 0x01;
    const tampered = { iv: ct.iv, ciphertext: ct.ciphertext, tag: tamperedTag };
    await expect(decryptChunk(key, tampered, new Uint8Array(0))).rejects.toThrow(AuthenticationError);
  });

  it('rejects tampered IV byte', async () => {
    const key = await generateKey();
    const ct = await encryptChunk(key, enc.encode('important message'), new Uint8Array(0));
    const tamperedIv = new Uint8Array(ct.iv);
    tamperedIv[0] = (tamperedIv[0] ?? 0) ^ 0x01;
    const tampered = { iv: tamperedIv, ciphertext: ct.ciphertext, tag: ct.tag };
    await expect(decryptChunk(key, tampered, new Uint8Array(0))).rejects.toThrow(AuthenticationError);
  });

  it('rejects decryption with wrong key', async () => {
    const keyA = await generateKey();
    const keyB = await generateKey();
    const ct = await encryptChunk(keyA, enc.encode('secret'), new Uint8Array(0));
    await expect(decryptChunk(keyB, ct, new Uint8Array(0))).rejects.toThrow(AuthenticationError);
  });
});

describe('encryptChunk / decryptChunk — input validation', () => {
  it('encryptChunk rejects empty plaintext', async () => {
    const key = await generateKey();
    await expect(encryptChunk(key, new Uint8Array(0), new Uint8Array(0))).rejects.toThrow(InvalidInputError);
  });

  it('encryptChunk rejects oversize AAD (> 1 MiB)', async () => {
    const key = await generateKey();
    const oversizeAad = new Uint8Array(1_048_577); // 1 MiB + 1 byte
    await expect(encryptChunk(key, enc.encode('hi'), oversizeAad)).rejects.toThrow(InvalidInputError);
  });

  it('decryptChunk rejects IV of length != 12', async () => {
    const key = await generateKey();
    const ct = await encryptChunk(key, enc.encode('hi'), new Uint8Array(0));
    const bad = { iv: ct.iv.slice(0, 11), ciphertext: ct.ciphertext, tag: ct.tag };
    await expect(decryptChunk(key, bad, new Uint8Array(0))).rejects.toThrow(InvalidInputError);
  });

  it('decryptChunk rejects tag of length != 16', async () => {
    const key = await generateKey();
    const ct = await encryptChunk(key, enc.encode('hi'), new Uint8Array(0));
    const bad = { iv: ct.iv, ciphertext: ct.ciphertext, tag: ct.tag.slice(0, 15) };
    await expect(decryptChunk(key, bad, new Uint8Array(0))).rejects.toThrow(InvalidInputError);
  });

  it('decryptChunk rejects oversize AAD', async () => {
    const key = await generateKey();
    const ct = await encryptChunk(key, enc.encode('hi'), new Uint8Array(0));
    const oversizeAad = new Uint8Array(1_048_577);
    await expect(decryptChunk(key, ct, oversizeAad)).rejects.toThrow(InvalidInputError);
  });
});

describe('encryptChunk — key exhaustion', () => {
  it('throws KeyExhaustedError at 2^32 + 1 invocations (mocked via counter)', async () => {
    const key = await generateKey();
    // Fast-forward the counter to one below ceiling so the next encrypt brings us to 2^32 exactly.
    _internals(key).counter._setValueForTesting(4_294_967_295);

    // This call should succeed (counter: 4_294_967_295 -> 4_294_967_296).
    await encryptChunk(key, enc.encode('last allowed'), new Uint8Array(0));
    expect(key.invocations).toBe(4_294_967_296);

    // This call must throw without performing any encryption.
    await expect(
      encryptChunk(key, enc.encode('over the ceiling'), new Uint8Array(0)),
    ).rejects.toThrow(KeyExhaustedError);

    // Counter MUST remain at ceiling after the throw (not advance).
    expect(key.invocations).toBe(4_294_967_296);
  });

  it('throws KeyExhaustedError immediately when already at ceiling', async () => {
    const key = await generateKey();
    _internals(key).counter._setValueForTesting(4_294_967_296);
    await expect(
      encryptChunk(key, enc.encode('nope'), new Uint8Array(0)),
    ).rejects.toThrow(KeyExhaustedError);
  });
});
