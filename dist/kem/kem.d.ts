export interface KemKeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}
export interface EncapsulationResult {
    sharedSecret: Uint8Array;
    enc: Uint8Array;
}
export interface Kem {
    readonly id: string;
    readonly publicKeySize: number;
    readonly privateKeySize: number;
    readonly encSize: number;
    readonly sharedSecretSize: number;
    generateKeyPair(): Promise<KemKeyPair>;
    encapsulate(publicKey: Uint8Array): Promise<EncapsulationResult>;
    decapsulate(enc: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
}
//# sourceMappingURL=kem.d.ts.map