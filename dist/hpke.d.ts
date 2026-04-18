import type { Kem } from './kem/kem.js';
/**
 * HPKE Key Schedule (RFC 9180 Section 5.1).
 * Exported with underscore prefix for test-only use — not in public API.
 */
export declare function _keySchedule(mode: number, sharedSecret: Uint8Array, info: Uint8Array, suiteId: Uint8Array, nk: number, nn: number): Promise<{
    key: Uint8Array;
    baseNonce: Uint8Array;
}>;
export interface SealResult {
    enc: Uint8Array;
    ciphertext: Uint8Array;
    iv: Uint8Array;
    tag: Uint8Array;
}
/**
 * HPKE Base mode SealBase (RFC 9180 Section 5.1).
 * Single-shot: encrypts plaintext under pkR using the KEM shared secret.
 */
export declare function sealBase(kem: Kem, pkR: Uint8Array, info: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<SealResult>;
export interface CiphertextParts {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    tag: Uint8Array;
}
/**
 * HPKE Base mode OpenBase (RFC 9180 Section 5.1).
 * Single-shot: decrypts ciphertext using skR and the KEM shared secret.
 */
export declare function openBase(kem: Kem, enc: Uint8Array, skR: Uint8Array, info: Uint8Array, aad: Uint8Array, ct: CiphertextParts): Promise<Uint8Array>;
//# sourceMappingURL=hpke.d.ts.map