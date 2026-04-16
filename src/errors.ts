/** Base class for all errors thrown by the eternis-crypto library. */
export class EternisCryptoError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = this.constructor.name;
  }
}

/** Thrown on GCM tag mismatch — wrong key, wrong AAD, tampered ciphertext, or tampered IV. */
export class AuthenticationError extends EternisCryptoError {}

/** Thrown when a key has reached its maximum number of allowed invocations (2^32). */
export class KeyExhaustedError extends EternisCryptoError {}

/** Thrown on input-size violations, wrong-length IVs, wrong-length tags, or empty plaintext. */
export class InvalidInputError extends EternisCryptoError {}
