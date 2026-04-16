import { KeyExhaustedError } from '../errors.js';

/**
 * Per-key invocation counter.
 *
 * NIST SP 800-38D §8.3 (Dworkin 2007) caps an RBG-based-IV AES-GCM key at
 * 2^32 invocations. Once the counter hits this value, any further encrypt
 * call must fail — continuing risks an IV collision with probability
 * greater than 2^-32, which is the mandated limit.
 */
export class InvocationCounter {
  #value = 0;
  readonly #max: number;

  constructor(max: number) {
    if (!Number.isInteger(max) || max <= 0) {
      throw new Error('InvocationCounter: max must be a positive integer');
    }
    this.#max = max;
  }

  get value(): number {
    return this.#value;
  }

  get max(): number {
    return this.#max;
  }

  /** Increment by 1. Throws KeyExhaustedError if already at max. */
  increment(): void {
    if (this.#value >= this.#max) {
      throw new KeyExhaustedError(
        `key has reached the maximum of ${String(this.#max)} invocations; generate a new key`,
      );
    }
    this.#value += 1;
  }

  /** Test-only: fast-forward the counter without performing real encryptions. */
  _setValueForTesting(value: number): void {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error('_setValueForTesting: value must be a non-negative integer');
    }
    this.#value = value;
  }
}
