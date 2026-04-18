import { describe, expect, it } from 'vitest';
import { DHKEM_X25519 } from '../src/kem/dhkem-x25519.js';
import { hexToBytes, bytesToHex } from './helpers/parse-rsp.js';

describe('DHKEM-X25519 properties', () => {
  it('has correct id', () => {
    expect(DHKEM_X25519.id).toBe('DHKEM-X25519-HKDF-SHA256');
  });

  it('has correct sizes', () => {
    expect(DHKEM_X25519.publicKeySize).toBe(32);
    expect(DHKEM_X25519.privateKeySize).toBe(64); // sk(32) || pk(32)
    expect(DHKEM_X25519.encSize).toBe(32);
    expect(DHKEM_X25519.sharedSecretSize).toBe(32);
  });
});

describe('DHKEM-X25519 generateKeyPair', () => {
  it('produces keys of correct sizes', async () => {
    const { publicKey, privateKey } = await DHKEM_X25519.generateKeyPair();
    expect(publicKey.length).toBe(32);
    expect(privateKey.length).toBe(64);
  });

  it('embeds public key in private key bytes 32..64', async () => {
    const { publicKey, privateKey } = await DHKEM_X25519.generateKeyPair();
    expect(Array.from(privateKey.slice(32))).toEqual(Array.from(publicKey));
  });
});

describe('DHKEM-X25519 round-trip', () => {
  it('encapsulate then decapsulate produces matching shared secret', async () => {
    const { publicKey, privateKey } = await DHKEM_X25519.generateKeyPair();
    const { sharedSecret: ss1, enc } = await DHKEM_X25519.encapsulate(publicKey);

    expect(enc.length).toBe(32);
    expect(ss1.length).toBe(32);

    const ss2 = await DHKEM_X25519.decapsulate(enc, privateKey);
    expect(Array.from(ss2)).toEqual(Array.from(ss1));
  });

  it('wrong private key produces different shared secret', async () => {
    const kp1 = await DHKEM_X25519.generateKeyPair();
    const kp2 = await DHKEM_X25519.generateKeyPair();

    const { sharedSecret: ss1, enc } = await DHKEM_X25519.encapsulate(kp1.publicKey);
    const ss2 = await DHKEM_X25519.decapsulate(enc, kp2.privateKey);

    expect(Array.from(ss2)).not.toEqual(Array.from(ss1));
  });
});

describe('DHKEM-X25519 RFC 9180 A.1.1 vector', () => {
  // RFC 9180 Appendix A.1.1 — Base mode, DHKEM(X25519, HKDF-SHA256)
  const skEm = hexToBytes('52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736');
  const pkEm = hexToBytes('37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431');
  const skRm = hexToBytes('4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8');
  const pkRm = hexToBytes('3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d');
  const expectedSharedSecret = 'fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc';

  it('_extractAndExpand produces correct shared_secret from known DH and kem_context', async () => {
    const { _extractAndExpand, _dh } = await import('../src/kem/dhkem-x25519.js');

    // Compute DH(skEm, pkRm) using Web Crypto
    const dhResult = await _dh(skEm, pkRm);

    // kem_context = enc || pkRm = pkEm || pkRm
    const kemContext = new Uint8Array(64);
    kemContext.set(pkEm, 0);
    kemContext.set(pkRm, 32);

    const sharedSecret = await _extractAndExpand(dhResult, kemContext);
    expect(bytesToHex(sharedSecret)).toBe(expectedSharedSecret);
  });

  it('decapsulate with vector keys produces correct shared_secret', async () => {
    // Build the 64-byte private key: sk(32) || pk(32)
    const recipientSk = new Uint8Array(64);
    recipientSk.set(skRm, 0);
    recipientSk.set(pkRm, 32);

    // enc = pkEm (the ephemeral public key)
    const enc = pkEm;

    const sharedSecret = await DHKEM_X25519.decapsulate(enc, recipientSk);
    expect(bytesToHex(sharedSecret)).toBe(expectedSharedSecret);
  });
});
