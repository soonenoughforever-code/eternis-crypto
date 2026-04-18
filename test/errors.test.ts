import { describe, expect, it } from 'vitest';
import {
  EternisCryptoError,
  AuthenticationError,
  KeyExhaustedError,
  InvalidInputError,
  DecapsulationError,
  KeyWrappingError,
} from '../src/errors.js';

describe('errors', () => {
  it('EternisCryptoError is an Error with correct name and message', () => {
    const e = new EternisCryptoError('base');
    expect(e).toBeInstanceOf(Error);
    expect(e).toBeInstanceOf(EternisCryptoError);
    expect(e.name).toBe('EternisCryptoError');
    expect(e.message).toBe('base');
  });

  it('AuthenticationError extends EternisCryptoError', () => {
    const e = new AuthenticationError('tag mismatch');
    expect(e).toBeInstanceOf(EternisCryptoError);
    expect(e).toBeInstanceOf(AuthenticationError);
    expect(e.name).toBe('AuthenticationError');
  });

  it('KeyExhaustedError extends EternisCryptoError', () => {
    const e = new KeyExhaustedError('ceiling');
    expect(e).toBeInstanceOf(EternisCryptoError);
    expect(e).toBeInstanceOf(KeyExhaustedError);
    expect(e.name).toBe('KeyExhaustedError');
  });

  it('InvalidInputError extends EternisCryptoError', () => {
    const e = new InvalidInputError('too big');
    expect(e).toBeInstanceOf(EternisCryptoError);
    expect(e).toBeInstanceOf(InvalidInputError);
    expect(e.name).toBe('InvalidInputError');
  });

  it('preserves cause when provided', () => {
    const cause = new Error('inner');
    const e = new AuthenticationError('outer', { cause });
    expect(e.cause).toBe(cause);
  });
});

describe('DecapsulationError', () => {
  it('extends EternisCryptoError', () => {
    const err = new DecapsulationError('test');
    expect(err).toBeInstanceOf(EternisCryptoError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('DecapsulationError');
    expect(err.message).toBe('test');
  });
});

describe('KeyWrappingError', () => {
  it('extends EternisCryptoError', () => {
    const err = new KeyWrappingError('test');
    expect(err).toBeInstanceOf(EternisCryptoError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('KeyWrappingError');
    expect(err.message).toBe('test');
  });
});
