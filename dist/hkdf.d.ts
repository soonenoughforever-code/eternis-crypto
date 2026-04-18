/** Concatenate multiple Uint8Arrays into one. */
export declare function concat(...arrays: Uint8Array[]): Uint8Array;
/** Encode a non-negative integer as a big-endian byte string of the given length. */
export declare function i2osp(value: number, length: number): Uint8Array;
/**
 * HKDF-Extract (RFC 5869 Section 2.2).
 * PRK = HMAC-SHA-256(salt, IKM)
 */
export declare function extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>;
/**
 * HKDF-Expand (RFC 5869 Section 2.3).
 * OKM = T(1) || T(2) || ... where T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i)
 */
export declare function expand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
/**
 * RFC 9180 Section 4 — LabeledExtract.
 * labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
 * return Extract(salt, labeled_ikm)
 */
export declare function labeledExtract(salt: Uint8Array, label: string, ikm: Uint8Array, suiteId: Uint8Array): Promise<Uint8Array>;
/**
 * RFC 9180 Section 4 — LabeledExpand.
 * labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
 * return Expand(prk, labeled_info, L)
 */
export declare function labeledExpand(prk: Uint8Array, label: string, info: Uint8Array, length: number, suiteId: Uint8Array): Promise<Uint8Array>;
//# sourceMappingURL=hkdf.d.ts.map