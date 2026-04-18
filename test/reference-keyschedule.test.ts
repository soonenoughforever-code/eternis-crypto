import { describe, expect, it } from 'vitest';
import { refKeySchedule, buildRefSuiteId } from './reference-keyschedule.js';
import { hexToBytes, bytesToHex } from './helpers/parse-rsp.js';

// RFC 9180 A.1.1 shared values (same for any AEAD)
const sharedSecret = hexToBytes('fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc');
const info = hexToBytes('4f6465206f6e2061204772656369616e2055726e');

describe('reference key schedule — A.1.1 AES-128-GCM (proves reference is correct)', () => {
  // Suite: DHKEM(X25519) + HKDF-SHA256 + AES-128-GCM
  const suiteId = buildRefSuiteId(0x0020, 0x0001, 0x0001);

  it('psk_id_hash matches A.1.1', () => {
    const { pskIdHash } = refKeySchedule(0x00, sharedSecret, info, suiteId, 16, 12);
    expect(bytesToHex(pskIdHash)).toBe('725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07');
  });

  it('info_hash matches A.1.1', () => {
    const { infoHash } = refKeySchedule(0x00, sharedSecret, info, suiteId, 16, 12);
    expect(bytesToHex(infoHash)).toBe('cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449');
  });

  it('key_schedule_context matches A.1.1', () => {
    const { ksContext } = refKeySchedule(0x00, sharedSecret, info, suiteId, 16, 12);
    expect(bytesToHex(ksContext)).toBe(
      '00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07' +
      'cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449',
    );
  });

  it('secret matches A.1.1', () => {
    const { secret } = refKeySchedule(0x00, sharedSecret, info, suiteId, 16, 12);
    expect(bytesToHex(secret)).toBe('12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397');
  });

  it('key matches A.1.1 (Nk=16)', () => {
    const { key } = refKeySchedule(0x00, sharedSecret, info, suiteId, 16, 12);
    expect(bytesToHex(key)).toBe('4531685d41d65f03dc48f6b8302c05b0');
  });

  it('base_nonce matches A.1.1 (Nn=12)', () => {
    const { baseNonce } = refKeySchedule(0x00, sharedSecret, info, suiteId, 16, 12);
    expect(bytesToHex(baseNonce)).toBe('56d890e5accaaf011cff4b7d');
  });
});

describe('reference key schedule — AES-256-GCM suite (generates our missing vectors)', () => {
  // Suite: DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM
  const suiteId = buildRefSuiteId(0x0020, 0x0001, 0x0002);

  it('produces 32-byte key and 12-byte nonce', () => {
    const { key, baseNonce } = refKeySchedule(0x00, sharedSecret, info, suiteId, 32, 12);
    expect(key.length).toBe(32);
    expect(baseNonce.length).toBe(12);
  });

  it('differs from AES-128-GCM suite (suite_id changed)', () => {
    const aes128Suite = buildRefSuiteId(0x0020, 0x0001, 0x0001);
    const aes128 = refKeySchedule(0x00, sharedSecret, info, aes128Suite, 16, 12);
    const aes256 = refKeySchedule(0x00, sharedSecret, info, suiteId, 32, 12);

    // Different suite_id → different intermediate values
    expect(bytesToHex(aes256.pskIdHash)).not.toBe(bytesToHex(aes128.pskIdHash));
    expect(bytesToHex(aes256.secret)).not.toBe(bytesToHex(aes128.secret));
    expect(bytesToHex(aes256.baseNonce)).not.toBe(bytesToHex(aes128.baseNonce));
  });
});
