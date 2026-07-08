/**
 * Preservation pipeline — single preserve()/recover() API chaining
 * AES-256-GCM, Shamir splitting, and shard encryption (HPKE + ML-DSA-65).
 *
 * References:
 * - PreVeil (2024) — DEK → Shamir → encrypted shares pattern
 * - Crypt4GH (GA4GH) — fresh DEK per file, no key reuse
 * - NIST SP 800-56C — single-purpose derived keys
 */
import type { Kem } from './kem/kem.js';
import type { PreservationPackage } from './types.js';
/**
 * Draw a random 32-byte DEK whose big-endian value lies in the Shamir field
 * [0, P), P = 2^256 - 189. Rejection-samples the ~189/2^256 out-of-field draws
 * so preserve() can never emit a DEK that splitKey would reduce mod P (F3).
 * The `draw` parameter is injectable for testing; production uses the CSPRNG.
 */
export declare function _drawInFieldSecret(draw?: (n: number) => Uint8Array): Uint8Array;
/**
 * Preserve data by encrypting it and distributing the key among custodians.
 *
 * Flow: generate DEK → AES encrypt → Shamir split DEK → sign+encrypt each shard.
 * The DEK never appears in the output — it is fully decomposed into shards.
 */
export declare function preserve(data: Uint8Array, custodianPublicKeys: Uint8Array[], ownerSigningKey: Uint8Array, options?: {
    threshold?: number;
    kem?: Kem;
}): Promise<PreservationPackage>;
/**
 * Recover preserved data using custodian private keys.
 *
 * Flow: decrypt+verify shards → Shamir combine → AES decrypt.
 *
 * @param custodianPrivateKeys - One entry per custodian participating in
 *   recovery. `index` is the **0-based slot** of that custodian's shard in
 *   `pkg.encryptedShards` (i.e. their position in the `custodianPublicKeys`
 *   array passed to preserve()), NOT the 1-based Shamir point index. Each
 *   `privateKey` must be the private key of the custodian at that slot.
 */
export declare function recover(pkg: PreservationPackage, custodianPrivateKeys: {
    index: number;
    privateKey: Uint8Array;
}[], ownerVerifyKey: Uint8Array, options?: {
    kem?: Kem;
}): Promise<Uint8Array>;
//# sourceMappingURL=pipeline.d.ts.map