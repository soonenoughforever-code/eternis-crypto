/**
 * Per-key invocation counter.
 *
 * NIST SP 800-38D §8.3 (Dworkin 2007) caps an RBG-based-IV AES-GCM key at
 * 2^32 invocations. Once the counter hits this value, any further encrypt
 * call must fail — continuing risks an IV collision with probability
 * greater than 2^-32, which is the mandated limit.
 */
export declare class InvocationCounter {
    #private;
    constructor(max: number);
    get value(): number;
    get max(): number;
    /** Increment by 1. Throws KeyExhaustedError if already at max. */
    increment(): void;
    /** Test-only: fast-forward the counter without performing real encryptions. */
    _setValueForTesting(value: number): void;
}
//# sourceMappingURL=invocation-counter.d.ts.map