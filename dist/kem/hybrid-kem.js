import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { concat } from '../hkdf.js';
// XWingLabel = "\./" + "/^\" = hex 5c2e2f2f5e5c (6 bytes)
// From X-Wing spec (Barbosa et al. 2024), Figure 1
const XWING_LABEL = new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
// Key sizes per FIPS 203 (ML-KEM-768) and RFC 7748 (X25519)
const MLKEM_PK_SIZE = 1184;
const MLKEM_SK_SIZE = 2400;
const MLKEM_CT_SIZE = 1088;
const X25519_KEY_SIZE = 32;
// X25519 PKCS8 ASN.1 prefix for importing raw private keys into Web Crypto
const X25519_PKCS8_PREFIX = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
/**
 * X-Wing combiner: SHA3-256(XWingLabel || ss_M || ss_X || ct_X || pk_X)
 * Per NIST SP 800-227 Section 4.6.3 (KeyCombine_H^CCA) and X-Wing spec.
 * Including ct_X and pk_X is required for IND-CCA security.
 */
export function _combiner(ssM, ssX, ctX, pkX) {
    const input = concat(XWING_LABEL, ssM, ssX, ctX, pkX);
    return sha3_256(input);
}
function wrapPkcs8(rawSk) {
    const pkcs8 = new Uint8Array(48);
    pkcs8.set(X25519_PKCS8_PREFIX);
    pkcs8.set(rawSk, 16);
    return pkcs8;
}
export const HYBRID_X25519_MLKEM768 = {
    id: 'Hybrid-X25519-MLKEM768',
    publicKeySize: MLKEM_PK_SIZE + X25519_KEY_SIZE, // 1216
    privateKeySize: MLKEM_SK_SIZE + X25519_KEY_SIZE + X25519_KEY_SIZE, // 2464
    encSize: MLKEM_CT_SIZE + X25519_KEY_SIZE, // 1120
    sharedSecretSize: 32,
    async generateKeyPair() {
        // ML-KEM-768 keypair
        const mlkem = ml_kem768.keygen();
        // X25519 keypair via Web Crypto
        const x25519kp = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        const pkX = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', x25519kp.publicKey));
        const pkcs8 = new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', x25519kp.privateKey));
        const skX = pkcs8.slice(16, 48);
        // publicKey = pk_M(1184) || pk_X(32) = 1216 bytes
        const publicKey = concat(mlkem.publicKey, pkX);
        // privateKey = sk_M(2400) || sk_X(32) || pk_X(32) = 2464 bytes
        const privateKey = concat(mlkem.secretKey, skX, pkX);
        return { publicKey, privateKey };
    },
    async encapsulate(publicKey) {
        // Split public key
        const pkM = publicKey.slice(0, MLKEM_PK_SIZE);
        const pkX = publicKey.slice(MLKEM_PK_SIZE);
        // ML-KEM-768 encapsulation
        const { cipherText: ctM, sharedSecret: ssM } = ml_kem768.encapsulate(pkM);
        // X25519 ephemeral DH
        const ephemeral = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        const ctX = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', ephemeral.publicKey));
        const pkXKey = await globalThis.crypto.subtle.importKey('raw', pkX, 'X25519', true, []);
        const ssX = new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: 'X25519', public: pkXKey }, ephemeral.privateKey, 256));
        // X-Wing combiner
        const sharedSecret = _combiner(ssM, ssX, ctX, pkX);
        // enc = ct_M(1088) || ct_X(32) = 1120 bytes
        const enc = concat(ctM, ctX);
        return { sharedSecret, enc };
    },
    async decapsulate(enc, privateKey) {
        // Split enc
        const ctM = enc.slice(0, MLKEM_CT_SIZE);
        const ctX = enc.slice(MLKEM_CT_SIZE);
        // Split private key: sk_M(2400) || sk_X(32) || pk_X(32)
        const skM = privateKey.slice(0, MLKEM_SK_SIZE);
        const skX = privateKey.slice(MLKEM_SK_SIZE, MLKEM_SK_SIZE + X25519_KEY_SIZE);
        const pkX = privateKey.slice(MLKEM_SK_SIZE + X25519_KEY_SIZE);
        // ML-KEM-768 decapsulation
        const ssM = ml_kem768.decapsulate(ctM, skM);
        // X25519 DH(skX, ctX)
        const skXKey = await globalThis.crypto.subtle.importKey('pkcs8', wrapPkcs8(skX), 'X25519', false, ['deriveBits']);
        const ctXKey = await globalThis.crypto.subtle.importKey('raw', ctX, 'X25519', true, []);
        const ssX = new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: 'X25519', public: ctXKey }, skXKey, 256));
        // X-Wing combiner
        return _combiner(ssM, ssX, ctX, pkX);
    },
};
//# sourceMappingURL=hybrid-kem.js.map