import { describe, expect, it, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { _encryptChunkWithIV } from '../src/aes-gcm.js';
import { _importRawKey } from '../src/keys.js';
import { parseGcmRsp, hexToBytes, bytesToHex, type GcmVector } from './helpers/parse-rsp.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('NIST CAVP AES-256 GCM encrypt vectors', () => {
  let vectors: GcmVector[];

  beforeAll(() => {
    const path = resolve(__dirname, '..', 'vectors', 'gcmEncryptExtIV256.rsp');
    const contents = readFileSync(path, 'utf-8');
    // Filter to vectors that match our fixed parameters:
    //   IVlen = 96  (12-byte IV — the only length our implementation accepts)
    //   Taglen = 128 (16-byte tag — the only tag length our implementation produces)
    // The NIST file also contains IVlen = 8, 1024 and Taglen = 32..120 groups
    // intended for implementations that support variable parameters; those are
    // not applicable to eternis-crypto.
    vectors = parseGcmRsp(contents).filter(v => v.ivLenBits === 96 && v.tagLenBits === 128);
  });

  it('parsed at least 300 applicable vectors (IVlen=96, Taglen=128)', () => {
    // The full file has 7875 vectors across 3 IVlen × 7 Taglen × 25 PT/AAD
    // combinations. After filtering to our parameters (96-bit IV, 128-bit tag),
    // we expect exactly 375 vectors (5 PTlen × 5 AADlen × 15 per group).
    expect(vectors.length).toBeGreaterThan(300);
  });

  it('every vector: our ciphertext and tag match NIST exactly', async () => {
    let mismatches = 0;
    const errors: string[] = [];
    for (let i = 0; i < vectors.length; i++) {
      const v = vectors[i]!;
      const keyBytes = hexToBytes(v.keyHex);
      const iv = hexToBytes(v.ivHex);
      const pt = hexToBytes(v.ptHex);
      const aad = hexToBytes(v.aadHex);
      const key = await _importRawKey(keyBytes);
      const result = await _encryptChunkWithIV(key, pt, aad, iv);
      const gotCt = bytesToHex(result.ciphertext);
      const gotTag = bytesToHex(result.tag);
      if (gotCt !== v.ctHex || gotTag !== v.tagHex) {
        mismatches++;
        if (errors.length < 3) {
          errors.push(
            `vector ${String(i)}: expected CT=${v.ctHex} Tag=${v.tagHex}, got CT=${gotCt} Tag=${gotTag}`,
          );
        }
      }
    }
    if (mismatches > 0) {
      throw new Error(`${String(mismatches)} / ${String(vectors.length)} vectors mismatched. First few:\n${errors.join('\n')}`);
    }
  }, 120_000);
});
