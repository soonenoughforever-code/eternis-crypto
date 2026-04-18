import { HYBRID_X25519_MLKEM768 } from './kem/hybrid-kem.js';
import { sealBase, openBase } from './hpke.js';
import { InvalidInputError } from './errors.js';
const DEK_BYTES = 32;
/**
 * Generate a master keypair for key wrapping.
 * Default KEM: Hybrid-X25519-MLKEM768 (post-quantum).
 */
export async function generateMasterKeyPair(kem) {
    const k = kem ?? HYBRID_X25519_MLKEM768;
    const { publicKey, privateKey } = await k.generateKeyPair();
    return { publicKey, privateKey, kemId: k.id };
}
/**
 * Wrap a DEK under a master public key using HPKE Base mode.
 * The DEK must be exactly 32 bytes (AES-256 key).
 * Default KEM: Hybrid-X25519-MLKEM768.
 */
export async function wrapKey(dek, masterPublicKey, options) {
    if (dek.length !== DEK_BYTES) {
        throw new InvalidInputError(`DEK must be exactly ${String(DEK_BYTES)} bytes, got ${String(dek.length)}`);
    }
    const kem = options?.kem ?? HYBRID_X25519_MLKEM768;
    const info = options?.info ?? new Uint8Array(0);
    if (masterPublicKey.length !== kem.publicKeySize) {
        throw new InvalidInputError(`masterPublicKey must be ${String(kem.publicKeySize)} bytes for ${kem.id}, got ${String(masterPublicKey.length)}`);
    }
    const sealed = await sealBase(kem, masterPublicKey, info, new Uint8Array(0), dek);
    return {
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        iv: sealed.iv,
        tag: sealed.tag,
        kemId: kem.id,
    };
}
/**
 * Unwrap a DEK using the master private key.
 * Throws AuthenticationError if the tag doesn't verify.
 * Throws InvalidInputError if kemId doesn't match.
 */
export async function unwrapKey(wrapped, masterPrivateKey, options) {
    const kem = options?.kem ?? HYBRID_X25519_MLKEM768;
    const info = options?.info ?? new Uint8Array(0);
    if (wrapped.kemId !== kem.id) {
        throw new InvalidInputError(`KEM mismatch: wrapped key uses "${wrapped.kemId}" but unwrap was called with "${kem.id}"`);
    }
    if (wrapped.enc.length !== kem.encSize) {
        throw new InvalidInputError(`enc must be ${String(kem.encSize)} bytes for ${kem.id}, got ${String(wrapped.enc.length)}`);
    }
    return openBase(kem, wrapped.enc, masterPrivateKey, info, new Uint8Array(0), {
        ciphertext: wrapped.ciphertext,
        iv: wrapped.iv,
        tag: wrapped.tag,
    });
}
//# sourceMappingURL=key-wrap.js.map