/**
 * Shard encryption for custodian distribution.
 *
 * distributeShard() — sign a shard with the owner's ML-DSA-65 key,
 *   then encrypt under the custodian's HPKE public key.
 * recoverShard() — decrypt with the custodian's HPKE private key,
 *   then verify the owner's ML-DSA-65 signature.
 *
 * References:
 * - PreVeil (2024) Security Whitepaper — authenticated shard encryption
 * - NIST FIPS 204 — ML-DSA-65 post-quantum signatures
 * - RFC 9180 — HPKE Base mode encryption
 */
import type { Kem } from '../kem/kem.js';
import type { Shard, EncryptedShard } from '../types.js';
/**
 * Encrypt and sign a shard for distribution to a custodian.
 *
 * Signs the shard with the owner's ML-DSA-65 key (origin proof),
 * then encrypts under the custodian's HPKE public key (confidentiality).
 */
export declare function distributeShard(shard: Shard, custodianPublicKey: Uint8Array, ownerSigningKey: Uint8Array, options?: {
    kem?: Kem;
    info?: Uint8Array;
}): Promise<EncryptedShard>;
/**
 * Decrypt and verify a shard received from storage/transport.
 *
 * Decrypts with the custodian's HPKE private key, then verifies
 * the owner's ML-DSA-65 signature to confirm origin.
 */
export declare function recoverShard(encryptedShard: EncryptedShard, custodianPrivateKey: Uint8Array, ownerVerifyKey: Uint8Array, options?: {
    kem?: Kem;
    info?: Uint8Array;
}): Promise<Shard>;
//# sourceMappingURL=shard-encrypt.d.ts.map