import { describe, expect, it } from 'vitest';
import { InvocationCounter } from '../../src/internal/invocation-counter.js';
import { KeyExhaustedError } from '../../src/errors.js';

describe('InvocationCounter', () => {
  it('starts at 0', () => {
    const c = new InvocationCounter(100);
    expect(c.value).toBe(0);
  });

  it('exposes max', () => {
    const c = new InvocationCounter(100);
    expect(c.max).toBe(100);
  });

  it('increments on each call', () => {
    const c = new InvocationCounter(100);
    c.increment();
    expect(c.value).toBe(1);
    c.increment();
    expect(c.value).toBe(2);
  });

  it('reaches max exactly', () => {
    const c = new InvocationCounter(3);
    c.increment();
    c.increment();
    c.increment();
    expect(c.value).toBe(3);
  });

  it('throws KeyExhaustedError once at max', () => {
    const c = new InvocationCounter(3);
    c.increment();
    c.increment();
    c.increment();
    expect(() => c.increment()).toThrow(KeyExhaustedError);
  });

  it('does not advance value when throwing', () => {
    const c = new InvocationCounter(1);
    c.increment();
    expect(() => c.increment()).toThrow(KeyExhaustedError);
    expect(c.value).toBe(1);
  });

  it('rejects non-positive max', () => {
    expect(() => new InvocationCounter(0)).toThrow();
    expect(() => new InvocationCounter(-1)).toThrow();
    expect(() => new InvocationCounter(1.5)).toThrow();
  });

  it('_setValueForTesting fast-forwards', () => {
    const c = new InvocationCounter(10);
    c._setValueForTesting(9);
    expect(c.value).toBe(9);
    c.increment();
    expect(c.value).toBe(10);
    expect(() => c.increment()).toThrow(KeyExhaustedError);
  });
});
