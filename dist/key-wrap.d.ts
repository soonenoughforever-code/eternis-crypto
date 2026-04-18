import type { Kem } from './kem/kem.js';
import type { WrappedKey, MasterKeyPair } from './types.js';
/**
 * Generate a master keypair for key wrapping.
 * Default KEM: Hybrid-X25519-MLKEM768 (post-quantum).
 */
export declare function generateMasterKeyPair(kem?: Kem): Promise<MasterKeyPair>;
/**
 * Wrap a DEK under a master public key using HPKE Base mode.
 * The DEK must be exactly 32 bytes (AES-256 key).
 * Default KEM: Hybrid-X25519-MLKEM768.
 */
export declare function wrapKey(dek: Uint8Array, masterPublicKey: Uint8Array, options?: {
    kem?: Kem;
    info?: Uint8Array;
}): Promise<WrappedKey>;
/**
 * Unwrap a DEK using the master private key.
 * Throws AuthenticationError if the tag doesn't verify.
 * Throws InvalidInputError if kemId doesn't match.
 */
export declare function unwrapKey(wrapped: WrappedKey, masterPrivateKey: Uint8Array, options?: {
    kem?: Kem;
    info?: Uint8Array;
}): Promise<Uint8Array>;
//# sourceMappingURL=key-wrap.d.ts.map