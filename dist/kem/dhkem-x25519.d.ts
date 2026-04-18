import type { Kem } from './kem.js';
/** Test-only: raw X25519 DH. */
export declare function _dh(rawSk: Uint8Array, rawPk: Uint8Array): Promise<Uint8Array>;
/**
 * Test-only: ExtractAndExpand per RFC 9180 Section 4.1.
 * eae_prk = LabeledExtract("", "eae_prk", dh)
 * shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, 32)
 */
export declare function _extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Promise<Uint8Array>;
export declare const DHKEM_X25519: Kem;
//# sourceMappingURL=dhkem-x25519.d.ts.map