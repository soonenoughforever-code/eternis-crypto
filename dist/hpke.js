import { labeledExtract, labeledExpand, concat, i2osp } from './hkdf.js';
import { AuthenticationError } from './errors.js';
const TAG_BYTES = 16;
/** Build the HPKE suite_id: "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2) */
function buildSuiteId(kemId, kdfId, aeadId) {
    const prefix = new TextEncoder().encode('HPKE');
    return concat(prefix, i2osp(kemId, 2), i2osp(kdfId, 2), i2osp(aeadId, 2));
}
// DHKEM(X25519, HKDF-SHA256) KEM ID
const KEM_ID_DHKEM_X25519 = 0x0020;
// Hybrid KEM — private-use KEM ID
const KEM_ID_HYBRID = 0xff01;
// HKDF-SHA256 KDF ID
const KDF_ID = 0x0001;
// AES-256-GCM AEAD ID
const AEAD_ID = 0x0002;
// AES-256-GCM parameters
const NK = 32; // key length
const NN = 12; // nonce length
function kemIdFromString(id) {
    switch (id) {
        case 'DHKEM-X25519-HKDF-SHA256': return KEM_ID_DHKEM_X25519;
        case 'Hybrid-X25519-MLKEM768': return KEM_ID_HYBRID;
        default: throw new Error(`Unknown KEM id: ${id}`);
    }
}
/**
 * HPKE Key Schedule (RFC 9180 Section 5.1).
 * Exported with underscore prefix for test-only use — not in public API.
 */
export async function _keySchedule(mode, sharedSecret, info, suiteId, nk, nn) {
    const pskIdHash = await labeledExtract(new Uint8Array(0), 'psk_id_hash', new Uint8Array(0), suiteId);
    const infoHash = await labeledExtract(new Uint8Array(0), 'info_hash', info, suiteId);
    const ksContext = concat(new Uint8Array([mode]), pskIdHash, infoHash);
    const secret = await labeledExtract(sharedSecret, 'secret', new Uint8Array(0), suiteId);
    const key = await labeledExpand(secret, 'key', ksContext, nk, suiteId);
    const baseNonce = await labeledExpand(secret, 'base_nonce', ksContext, nn, suiteId);
    return { key, baseNonce };
}
/**
 * HPKE Base mode SealBase (RFC 9180 Section 5.1).
 * Single-shot: encrypts plaintext under pkR using the KEM shared secret.
 */
export async function sealBase(kem, pkR, info, aad, plaintext) {
    const { sharedSecret, enc } = await kem.encapsulate(pkR);
    const suiteId = buildSuiteId(kemIdFromString(kem.id), KDF_ID, AEAD_ID);
    const { key, baseNonce } = await _keySchedule(0x00, sharedSecret, info, suiteId, NK, NN);
    const cryptoKey = await globalThis.crypto.subtle.importKey('raw', key, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const combined = new Uint8Array(await globalThis.crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv: baseNonce,
        additionalData: aad,
        tagLength: 128,
    }, cryptoKey, plaintext));
    const ciphertext = combined.slice(0, combined.length - TAG_BYTES);
    const tag = combined.slice(combined.length - TAG_BYTES);
    return { enc, ciphertext, iv: baseNonce, tag };
}
/**
 * HPKE Base mode OpenBase (RFC 9180 Section 5.1).
 * Single-shot: decrypts ciphertext using skR and the KEM shared secret.
 */
export async function openBase(kem, enc, skR, info, aad, ct) {
    const sharedSecret = await kem.decapsulate(enc, skR);
    const suiteId = buildSuiteId(kemIdFromString(kem.id), KDF_ID, AEAD_ID);
    const { key, baseNonce } = await _keySchedule(0x00, sharedSecret, info, suiteId, NK, NN);
    const cryptoKey = await globalThis.crypto.subtle.importKey('raw', key, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const combined = new Uint8Array(ct.ciphertext.length + ct.tag.length);
    combined.set(ct.ciphertext, 0);
    combined.set(ct.tag, ct.ciphertext.length);
    try {
        return new Uint8Array(await globalThis.crypto.subtle.decrypt({
            name: 'AES-GCM',
            iv: baseNonce,
            additionalData: aad,
            tagLength: 128,
        }, cryptoKey, combined));
    }
    catch (cause) {
        throw new AuthenticationError('HPKE open failed: tag mismatch (wrong key, wrong AAD, or tampered ciphertext)', { cause });
    }
}
//# sourceMappingURL=hpke.js.map