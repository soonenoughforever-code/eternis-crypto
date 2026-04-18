import { describe, expect, it } from 'vitest';
import { extract, expand, labeledExtract, labeledExpand, concat, i2osp } from '../src/hkdf.js';
import { hexToBytes, bytesToHex } from './helpers/parse-rsp.js';

describe('concat', () => {
  it('concatenates multiple Uint8Arrays', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3]);
    const c = new Uint8Array([4, 5, 6]);
    expect(Array.from(concat(a, b, c))).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('handles empty arrays', () => {
    const a = new Uint8Array([1]);
    const empty = new Uint8Array(0);
    expect(Array.from(concat(a, empty, a))).toEqual([1, 1]);
  });
});

describe('i2osp', () => {
  it('encodes integers as big-endian bytes', () => {
    expect(Array.from(i2osp(0x0020, 2))).toEqual([0x00, 0x20]);
    expect(Array.from(i2osp(0x0001, 2))).toEqual([0x00, 0x01]);
    expect(Array.from(i2osp(0x00, 1))).toEqual([0x00]);
    expect(Array.from(i2osp(32, 2))).toEqual([0x00, 0x20]);
  });
});

describe('HKDF extract + expand (RFC 5869 Test Case 1)', () => {
  const ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const salt = hexToBytes('000102030405060708090a0b0c');
  const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
  const expectedPrk = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
  const expectedOkm = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';

  it('extract produces correct PRK', async () => {
    const prk = await extract(salt, ikm);
    expect(bytesToHex(prk)).toBe(expectedPrk);
  });

  it('expand produces correct OKM', async () => {
    const prk = hexToBytes(expectedPrk);
    const okm = await expand(prk, info, 42);
    expect(bytesToHex(okm)).toBe(expectedOkm);
  });
});

describe('HKDF extract + expand (RFC 5869 Test Case 3 — empty salt & info)', () => {
  const ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const expectedPrk = '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04';
  const expectedOkm = '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8';

  it('extract with empty salt', async () => {
    const prk = await extract(new Uint8Array(0), ikm);
    expect(bytesToHex(prk)).toBe(expectedPrk);
  });

  it('expand with empty info', async () => {
    const prk = hexToBytes(expectedPrk);
    const okm = await expand(prk, new Uint8Array(0), 42);
    expect(bytesToHex(okm)).toBe(expectedOkm);
  });
});

describe('HPKE LabeledExtract + LabeledExpand (RFC 9180 A.1.1 key schedule vectors)', () => {
  // HPKE suite_id for A.1: "HPKE" || 0x0020 || 0x0001 || 0x0001
  const hpkeSuiteId = (() => {
    const prefix = new TextEncoder().encode('HPKE');
    return concat(prefix, i2osp(0x0020, 2), i2osp(0x0001, 2), i2osp(0x0001, 2));
  })();

  const info = hexToBytes('4f6465206f6e2061204772656369616e2055726e');
  const expectedKsContext = '00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449';

  it('psk_id_hash matches A.1.1', async () => {
    const pskIdHash = await labeledExtract(new Uint8Array(0), 'psk_id_hash', new Uint8Array(0), hpkeSuiteId);
    const expected = expectedKsContext.slice(2, 66);
    expect(bytesToHex(pskIdHash)).toBe(expected);
  });

  it('info_hash matches A.1.1', async () => {
    const infoHash = await labeledExtract(new Uint8Array(0), 'info_hash', info, hpkeSuiteId);
    const expected = expectedKsContext.slice(66);
    expect(bytesToHex(infoHash)).toBe(expected);
  });

  it('secret matches A.1.1', async () => {
    const sharedSecret = hexToBytes('fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc');
    const secret = await labeledExtract(sharedSecret, 'secret', new Uint8Array(0), hpkeSuiteId);
    expect(bytesToHex(secret)).toBe('12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397');
  });

  it('key matches A.1.1 (Nk=16 for AES-128-GCM)', async () => {
    const secret = hexToBytes('12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397');
    const ksContext = hexToBytes(expectedKsContext);
    const key = await labeledExpand(secret, 'key', ksContext, 16, hpkeSuiteId);
    expect(bytesToHex(key)).toBe('4531685d41d65f03dc48f6b8302c05b0');
  });

  it('base_nonce matches A.1.1 (Nn=12)', async () => {
    const secret = hexToBytes('12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397');
    const ksContext = hexToBytes(expectedKsContext);
    const baseNonce = await labeledExpand(secret, 'base_nonce', ksContext, 12, hpkeSuiteId);
    expect(bytesToHex(baseNonce)).toBe('56d890e5accaaf011cff4b7d');
  });
});
