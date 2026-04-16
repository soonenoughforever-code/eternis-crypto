/**
 * Minimal parser for NIST CAVP `.rsp` (Response) files for AES-GCM test vectors.
 *
 * File format (simplified):
 *   - `#` lines are comments.
 *   - `[Name = Value]` lines are group headers (context for subsequent records).
 *   - Records are separated by blank lines.
 *   - Inside a record: `Name = HexValue` pairs (Key, IV, PT, AAD, CT, Tag).
 *   - A line containing only `FAIL` in a decrypt record indicates the expected result is rejection.
 */

export interface GcmVector {
  keyHex: string;
  ivHex: string;
  /** IV length in bits as declared in the group header (e.g. 96). */
  ivLenBits: number;
  /** Tag length in bits as declared in the group header (e.g. 128). */
  tagLenBits: number;
  ptHex: string;
  aadHex: string;
  ctHex: string;
  tagHex: string;
  /** True iff the record contains a FAIL line (decrypt vectors only). */
  expectedFail: boolean;
}

export function parseGcmRsp(contents: string): GcmVector[] {
  const lines = contents.split(/\r?\n/);
  const records: GcmVector[] = [];
  let current: Partial<GcmVector> = {};
  let fail = false;
  let currentIvLenBits = 96;   // updated when we see [IVlen = N]
  let currentTagLenBits = 128; // updated when we see [Taglen = N]

  const flush = (): void => {
    if (current.keyHex !== undefined && current.ivHex !== undefined && current.tagHex !== undefined) {
      records.push({
        keyHex: current.keyHex,
        ivHex: current.ivHex,
        ivLenBits: currentIvLenBits,
        tagLenBits: currentTagLenBits,
        ptHex: current.ptHex ?? '',
        aadHex: current.aadHex ?? '',
        ctHex: current.ctHex ?? '',
        tagHex: current.tagHex,
        expectedFail: fail,
      });
    }
    current = {};
    fail = false;
  };

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '') {
      flush();
      continue;
    }
    if (line.startsWith('#')) continue;
    if (line.startsWith('[')) {
      // Parse group headers like [IVlen = 96]
      const inner = line.slice(1, line.length - 1);
      const eqIdx = inner.indexOf('=');
      if (eqIdx >= 0) {
        const hName = inner.slice(0, eqIdx).trim();
        const hVal = inner.slice(eqIdx + 1).trim();
        if (hName === 'IVlen') {
          currentIvLenBits = parseInt(hVal, 10);
        } else if (hName === 'Taglen') {
          currentTagLenBits = parseInt(hVal, 10);
        }
      }
      continue;
    }
    if (line === 'FAIL') {
      fail = true;
      continue;
    }
    const eqIdx = line.indexOf('=');
    if (eqIdx < 0) continue;
    const name = line.slice(0, eqIdx).trim();
    const value = line.slice(eqIdx + 1).trim();
    switch (name) {
      case 'Count': break;
      case 'Key': current.keyHex = value; break;
      case 'IV': current.ivHex = value; break;
      case 'PT': current.ptHex = value; break;
      case 'AAD': current.aadHex = value; break;
      case 'CT': current.ctHex = value; break;
      case 'Tag': current.tagHex = value; break;
      default: break;
    }
  }
  flush();
  return records;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length input (${String(hex.length)})`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const pair = hex.substr(i * 2, 2);
    const byte = parseInt(pair, 16);
    if (Number.isNaN(byte) || !/^[0-9a-fA-F]{2}$/.test(pair)) {
      throw new Error(`hexToBytes: invalid hex at position ${String(i * 2)}: "${pair}"`);
    }
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}
