import { describe, expect, it, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decryptChunk } from '../src/aes-gcm.js';
import { _importRawKey } from '../src/keys.js';
import { AuthenticationError } from '../src/errors.js';
import { parseGcmRsp, hexToBytes, bytesToHex, type GcmVector } from './helpers/parse-rsp.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('NIST CAVP AES-256 GCM decrypt vectors', () => {
  let vectors: GcmVector[];

  beforeAll(() => {
    const path = resolve(__dirname, '..', 'vectors', 'gcmDecrypt256.rsp');
    const contents = readFileSync(path, 'utf-8');
    const allVectors = parseGcmRsp(contents);
    // Filter to our fixed parameters: IVlen=96, Taglen=128.
    vectors = allVectors.filter(v => v.ivLenBits === 96 && v.tagLenBits === 128);
  });

  it('parsed a meaningful number of applicable vectors', () => {
    // The decrypt file has multiple groups; only IVlen=96 + Taglen=128 applies to us.
    expect(vectors.length).toBeGreaterThan(100);
  });

  it('every pass vector decrypts correctly; every fail vector throws AuthenticationError', async () => {
    let passMismatches = 0;
    let failMisses = 0;
    const errors: string[] = [];

    for (let i = 0; i < vectors.length; i++) {
      const v = vectors[i]!;
      const keyBytes = hexToBytes(v.keyHex);
      const iv = hexToBytes(v.ivHex);
      const ct = hexToBytes(v.ctHex);
      const aad = hexToBytes(v.aadHex);
      const tag = hexToBytes(v.tagHex);
      const key = await _importRawKey(keyBytes);
      const ciphertext = { iv, ciphertext: ct, tag };

      if (v.expectedFail) {
        let threw = false;
        try {
          await decryptChunk(key, ciphertext, aad);
        } catch (e) {
          if (e instanceof AuthenticationError) threw = true;
        }
        if (!threw) {
          failMisses++;
          if (errors.length < 3) errors.push(`vector ${String(i)}: expected FAIL but decrypt succeeded`);
        }
      } else {
        try {
          const recovered = await decryptChunk(key, ciphertext, aad);
          const got = bytesToHex(recovered);
          if (got !== v.ptHex) {
            passMismatches++;
            if (errors.length < 3) errors.push(`vector ${String(i)}: expected PT=${v.ptHex}, got ${got}`);
          }
        } catch (e) {
          passMismatches++;
          if (errors.length < 3) errors.push(`vector ${String(i)}: expected pass but threw: ${String(e)}`);
        }
      }
    }

    if (passMismatches + failMisses > 0) {
      throw new Error(
        `decrypt vectors failed: ${String(passMismatches)} pass-mismatches + ${String(failMisses)} fail-misses of ${String(vectors.length)} total.\nFirst few:\n${errors.join('\n')}`,
      );
    }
  }, 120_000);
});
