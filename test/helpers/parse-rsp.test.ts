import { describe, expect, it } from 'vitest';
import { parseGcmRsp, hexToBytes, bytesToHex } from './parse-rsp.js';

describe('parseGcmRsp', () => {
  it('parses a single encrypt record', () => {
    const rsp =
      '# CAVS 14.0\n' +
      '[Keylen = 256]\n[IVlen = 96]\n[PTlen = 0]\n[AADlen = 0]\n[Taglen = 128]\n\n' +
      'Count = 0\n' +
      'Key = b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4\n' +
      'IV = 516c33929df5a3284ff463d7\n' +
      'PT = \nAAD = \nCT = \n' +
      'Tag = bdc1ac884d332457a1d2664f168c76f0\n\n';
    const v = parseGcmRsp(rsp);
    expect(v).toHaveLength(1);
    expect(v[0]!.keyHex).toBe('b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4');
    expect(v[0]!.ivHex).toBe('516c33929df5a3284ff463d7');
    expect(v[0]!.ptHex).toBe('');
    expect(v[0]!.aadHex).toBe('');
    expect(v[0]!.ctHex).toBe('');
    expect(v[0]!.tagHex).toBe('bdc1ac884d332457a1d2664f168c76f0');
    expect(v[0]!.expectedFail).toBe(false);
  });

  it('parses a FAIL decrypt record', () => {
    const rsp =
      'Count = 0\n' +
      `Key = ${'0'.repeat(64)}\n` +
      `IV = ${'0'.repeat(24)}\n` +
      'CT = deadbeef\nAAD = \n' +
      `Tag = ${'0'.repeat(32)}\n` +
      'FAIL\n\n';
    const v = parseGcmRsp(rsp);
    expect(v).toHaveLength(1);
    expect(v[0]!.expectedFail).toBe(true);
  });

  it('parses multiple records separated by blank lines', () => {
    const rsp =
      `Count = 0\nKey = ${'11'.repeat(32)}\nIV = ${'22'.repeat(12)}\n` +
      `PT = \nAAD = \nCT = \nTag = ${'33'.repeat(16)}\n\n` +
      `Count = 1\nKey = ${'44'.repeat(32)}\nIV = ${'55'.repeat(12)}\n` +
      `PT = \nAAD = \nCT = \nTag = ${'66'.repeat(16)}\n\n`;
    const v = parseGcmRsp(rsp);
    expect(v).toHaveLength(2);
    expect(v[0]!.keyHex).toBe('11'.repeat(32));
    expect(v[1]!.keyHex).toBe('44'.repeat(32));
  });

  it('ignores comment and group-header lines', () => {
    const rsp =
      '# comment line\n[Keylen = 256]\n\n[PTlen = 128]\n' +
      `Count = 0\nKey = ${'aa'.repeat(32)}\nIV = ${'bb'.repeat(12)}\n` +
      `PT = deadbeef\nAAD = \nCT = cafebabe\nTag = ${'cc'.repeat(16)}\n\n`;
    const v = parseGcmRsp(rsp);
    expect(v).toHaveLength(1);
    expect(v[0]!.ptHex).toBe('deadbeef');
    expect(v[0]!.ctHex).toBe('cafebabe');
  });
});

describe('hexToBytes / bytesToHex', () => {
  it('round-trips', () => {
    const hex = 'deadbeef';
    const bytes = hexToBytes(hex);
    expect(bytes.length).toBe(4);
    expect(bytesToHex(bytes)).toBe(hex);
  });

  it('handles empty string', () => {
    expect(hexToBytes('').length).toBe(0);
    expect(bytesToHex(new Uint8Array(0))).toBe('');
  });

  it('rejects odd-length hex', () => {
    expect(() => hexToBytes('abc')).toThrow();
  });

  it('rejects invalid hex characters', () => {
    expect(() => hexToBytes('gg')).toThrow();
  });
});
