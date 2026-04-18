import type { Kem } from './kem.js';
/**
 * X-Wing combiner: SHA3-256(XWingLabel || ss_M || ss_X || ct_X || pk_X)
 * Per NIST SP 800-227 Section 4.6.3 (KeyCombine_H^CCA) and X-Wing spec.
 * Including ct_X and pk_X is required for IND-CCA security.
 */
export declare function _combiner(ssM: Uint8Array, ssX: Uint8Array, ctX: Uint8Array, pkX: Uint8Array): Uint8Array;
export declare const HYBRID_X25519_MLKEM768: Kem;
//# sourceMappingURL=hybrid-kem.d.ts.map