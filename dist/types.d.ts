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
/** The output of wrapKey — everything needed to unwrap the DEK later. */
export interface WrappedKey {
    /** KEM encapsulation (32 bytes for DHKEM, 1120 bytes for hybrid). */
    readonly enc: Uint8Array;
    /** AES-256-GCM encrypted DEK. */
    readonly ciphertext: Uint8Array;
    /** 12-byte nonce derived from HPKE key schedule. */
    readonly iv: Uint8Array;
    /** 16-byte GCM authentication tag. */
    readonly tag: Uint8Array;
    /** Identifies which KEM was used, for unwrap dispatch. */
    readonly kemId: string;
}
/** A master keypair for key wrapping operations. */
export interface MasterKeyPair {
    readonly publicKey: Uint8Array;
    readonly privateKey: Uint8Array;
    readonly kemId: string;
}
/** A single shard from a Shamir key split. */
export interface Shard {
    /** Point index on the polynomial (1–255). */
    readonly index: number;
    /** 32-byte shard value (the y-coordinate in GF(p)). */
    readonly value: Uint8Array;
    /** 32-byte HMAC-SHA256 authentication tag. */
    readonly mac: Uint8Array;
}
/** Configuration for splitKey. */
export interface SplitOptions {
    /** Minimum shards needed to reconstruct. Must be >= 2. */
    readonly threshold: number;
    /** Total shards to generate. Must be >= threshold and <= 255. */
    readonly shares: number;
}
/** Result of splitKey. */
export interface SplitResult {
    /** The generated shards, one per share. */
    readonly shards: readonly Shard[];
    /** The threshold that was used (needed for reconstruction metadata). */
    readonly threshold: number;
}
/** An ML-DSA-65 signing keypair. */
export interface SigningKeyPair {
    /** 1,952-byte ML-DSA-65 public (verification) key. */
    readonly publicKey: Uint8Array;
    /** 4,032-byte ML-DSA-65 secret (signing) key. */
    readonly secretKey: Uint8Array;
    /** Algorithm identifier: "ML-DSA-65". */
    readonly algorithmId: string;
}
/** An encrypted shard for distribution to a custodian. */
export interface EncryptedShard {
    /** HPKE encapsulation (KEM-dependent size). */
    readonly enc: Uint8Array;
    /** AES-256-GCM encrypted (shard + signature). */
    readonly ciphertext: Uint8Array;
    /** 12-byte nonce from HPKE key schedule. */
    readonly iv: Uint8Array;
    /** 16-byte GCM authentication tag. */
    readonly tag: Uint8Array;
    /** Identifies which KEM was used. */
    readonly kemId: string;
    /** Identifies which signature algorithm was used. */
    readonly sigAlgorithmId: string;
}
/** The complete output of a preserve() call — everything needed to recover the data. */
export interface PreservationPackage {
    /** AES-256-GCM encrypted data. */
    readonly encryptedData: {
        readonly ciphertext: Uint8Array;
        readonly iv: Uint8Array;
        readonly tag: Uint8Array;
    };
    /** One encrypted shard per custodian, each signed (ML-DSA-65) and encrypted (HPKE). */
    readonly encryptedShards: readonly EncryptedShard[];
    /** Pipeline metadata needed for recovery. */
    readonly metadata: {
        readonly version: string;
        readonly threshold: number;
        readonly totalShards: number;
        readonly kemId: string;
        readonly sigAlgorithmId: string;
    };
}
//# sourceMappingURL=types.d.ts.map