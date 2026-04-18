import type { Kem, KemKeyPair, EncapsulationResult } from './kem.js';
import { labeledExtract, labeledExpand, concat } from '../hkdf.js';

// "KEM" || I2OSP(0x0020, 2)
const KEM_SUITE_ID = (() => {
  const prefix = new TextEncoder().encode('KEM');
  return concat(prefix, new Uint8Array([0x00, 0x20]));
})();

const N_SECRET = 32;

// X25519 PKCS8 ASN.1 prefix (16 bytes). A raw 32-byte scalar is wrapped
// as: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.110 }, OCTET STRING { OCTET STRING { key } } }
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
  0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function wrapPkcs8(rawSk: Uint8Array): Uint8Array {
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(X25519_PKCS8_PREFIX);
  pkcs8.set(rawSk, 16);
  return pkcs8;
}

async function importPrivateKey(rawSk: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'pkcs8',
    wrapPkcs8(rawSk) as Uint8Array<ArrayBuffer>,
    'X25519',
    false,
    ['deriveBits'],
  );
}

async function importPublicKey(rawPk: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'raw',
    rawPk as Uint8Array<ArrayBuffer>,
    'X25519',
    true,
    [],
  );
}

/** Test-only: raw X25519 DH. */
export async function _dh(rawSk: Uint8Array, rawPk: Uint8Array): Promise<Uint8Array> {
  const sk = await importPrivateKey(rawSk);
  const pk = await importPublicKey(rawPk);
  return new Uint8Array(
    await globalThis.crypto.subtle.deriveBits(
      { name: 'X25519', public: pk },
      sk,
      256,
    ),
  );
}

/**
 * Test-only: ExtractAndExpand per RFC 9180 Section 4.1.
 * eae_prk = LabeledExtract("", "eae_prk", dh)
 * shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, 32)
 */
export async function _extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Promise<Uint8Array> {
  const eaePrk = await labeledExtract(new Uint8Array(0), 'eae_prk', dh, KEM_SUITE_ID);
  return labeledExpand(eaePrk, 'shared_secret', kemContext, N_SECRET, KEM_SUITE_ID);
}

export const DHKEM_X25519: Kem = {
  id: 'DHKEM-X25519-HKDF-SHA256',
  publicKeySize: 32,
  privateKeySize: 64, // sk(32) || pk(32) — pk embedded for kem_context in Decap
  encSize: 32,
  sharedSecretSize: 32,

  async generateKeyPair(): Promise<KemKeyPair> {
    const keyPair = await globalThis.crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits'],
    ) as CryptoKeyPair;
    const publicKey = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', keyPair.publicKey));
    const pkcs8 = new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
    const rawSk = pkcs8.slice(16, 48);

    // privateKey = sk(32) || pk(32)
    const privateKey = concat(rawSk, publicKey);
    return { publicKey, privateKey };
  },

  async encapsulate(publicKey: Uint8Array): Promise<EncapsulationResult> {
    // Generate ephemeral keypair
    const ephemeral = await globalThis.crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits'],
    ) as CryptoKeyPair;
    const pkE = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', ephemeral.publicKey));

    // DH(skE, pkR)
    const pkR = await importPublicKey(publicKey);
    const dh = new Uint8Array(
      await globalThis.crypto.subtle.deriveBits(
        { name: 'X25519', public: pkR },
        ephemeral.privateKey,
        256,
      ),
    );

    // kem_context = enc || pkR
    const enc = pkE;
    const kemContext = concat(enc, publicKey);

    const sharedSecret = await _extractAndExpand(dh, kemContext);
    return { sharedSecret, enc };
  },

  async decapsulate(enc: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    const rawSk = privateKey.slice(0, 32);
    const pkR = privateKey.slice(32, 64);

    // DH(skR, pkE)
    const skR = await importPrivateKey(rawSk);
    const pkE = await importPublicKey(enc);
    const dh = new Uint8Array(
      await globalThis.crypto.subtle.deriveBits(
        { name: 'X25519', public: pkE },
        skR,
        256,
      ),
    );

    // kem_context = enc || pkR
    const kemContext = concat(enc, pkR);

    return _extractAndExpand(dh, kemContext);
  },
};
