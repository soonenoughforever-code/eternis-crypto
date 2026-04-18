import { InvocationCounter } from './internal/invocation-counter.js';
interface KeyHandleInternals {
    cryptoKey: CryptoKey;
    counter: InvocationCounter;
}
/**
 * Opaque handle to a 256-bit AES key. The underlying CryptoKey is stored
 * with extractable=false, and its raw bytes are never exposed through
 * this handle. Callers see only algorithm metadata and the current
 * invocation count.
 */
export declare class KeyHandle {
    readonly algorithm: "AES-256-GCM";
    readonly maxInvocations: 4294967296;
    /** @internal — do not construct directly. Use generateKey(). */
    constructor();
    get invocations(): number;
}
/**
 * Module-private accessor used by src/aes-gcm.ts. Not re-exported from
 * src/index.ts, so consumers of the public API cannot reach the CryptoKey.
 */
export declare function _internals(handle: KeyHandle): KeyHandleInternals;
/**
 * Generate a fresh AES-256 key with extractable=false. The raw bytes
 * never leave the Web Crypto subsystem.
 */
export declare function generateKey(): Promise<KeyHandle>;
/**
 * Internal: import a raw 32-byte AES key into a KeyHandle.
 * Used by the preservation pipeline (to import a generated DEK) and
 * by tests (to import NIST CAVP test vectors). Not re-exported from
 * src/index.ts — callers must be internal to the library.
 */
export declare function _importRawKey(rawKey: Uint8Array): Promise<KeyHandle>;
export {};
//# sourceMappingURL=keys.d.ts.map