/** Base class for all errors thrown by the eternis-crypto library. */
export declare class EternisCryptoError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
/** Thrown on GCM tag mismatch — wrong key, wrong AAD, tampered ciphertext, or tampered IV. */
export declare class AuthenticationError extends EternisCryptoError {
}
/** Thrown when a key has reached its maximum number of allowed invocations (2^32). */
export declare class KeyExhaustedError extends EternisCryptoError {
}
/** Thrown on input-size violations, wrong-length IVs, wrong-length tags, or empty plaintext. */
export declare class InvalidInputError extends EternisCryptoError {
}
/** Thrown when KEM decapsulation fails. */
export declare class DecapsulationError extends EternisCryptoError {
}
/** Thrown when key wrapping or unwrapping fails for a non-authentication reason. */
export declare class KeyWrappingError extends EternisCryptoError {
}
/** Thrown when shard HMAC verification fails during reconstruction. */
export declare class ShardAuthenticationError extends EternisCryptoError {
}
/** Thrown when ML-DSA-65 signature verification fails during shard recovery. */
export declare class SignatureVerificationError extends EternisCryptoError {
}
//# sourceMappingURL=errors.d.ts.map