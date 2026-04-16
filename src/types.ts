/**
 * The complete output of an AES-256-GCM encryption call.
 * All three fields are required for decryption.
 */
export interface Ciphertext {
  /** 96-bit (12-byte) initialization vector, randomly generated per encryption. */
  readonly iv: Uint8Array;

  /** Ciphertext bytes. Same length as the input plaintext. */
  readonly ciphertext: Uint8Array;

  /** 128-bit (16-byte) GCM authentication tag. */
  readonly tag: Uint8Array;
}
