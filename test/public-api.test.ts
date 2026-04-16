import { describe, expect, it } from 'vitest';
import * as api from '../src/index.js';

describe('public API surface', () => {
  it('exports exactly the expected symbols', () => {
    const expected = new Set([
      'KeyHandle',
      'generateKey',
      'encryptChunk',
      'decryptChunk',
      'EternisCryptoError',
      'AuthenticationError',
      'KeyExhaustedError',
      'InvalidInputError',
    ]);
    const actual = new Set(Object.keys(api));
    expect(actual).toEqual(expected);
  });

  it('does not expose test-only or internal symbols', () => {
    const forbidden = ['_importKeyForTesting', '_encryptChunkWithIV', '_internals', 'InvocationCounter', 'randomBytes'];
    for (const name of forbidden) {
      expect(Object.keys(api)).not.toContain(name);
    }
  });
});
