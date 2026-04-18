import { describe, expect, it } from 'vitest';
import * as api from '../src/index.js';

describe('public API surface', () => {
  it('exports exactly the expected symbols', () => {
    const expected = new Set([
      // v0.1 — AES-256-GCM
      'KeyHandle',
      'generateKey',
      'encryptChunk',
      'decryptChunk',
      // v0.2 — HPKE key wrapping
      'DHKEM_X25519',
      'HYBRID_X25519_MLKEM768',
      'generateMasterKeyPair',
      'wrapKey',
      'unwrapKey',
      // v0.3 — Shamir key splitting
      'splitKey',
      'combineShards',
      // v0.4 — Shard encryption + ML-DSA-65 signing
      'generateSigningKeyPair',
      'sign',
      'verify',
      'distributeShard',
      'recoverShard',
      // v0.5 — Preservation pipeline
      'preserve',
      'recover',
      // Errors
      'EternisCryptoError',
      'AuthenticationError',
      'KeyExhaustedError',
      'InvalidInputError',
      'DecapsulationError',
      'KeyWrappingError',
      'ShardAuthenticationError',
      'SignatureVerificationError',
    ]);
    const actual = new Set(Object.keys(api));
    expect(actual).toEqual(expected);
  });

  it('does not expose test-only or internal symbols', () => {
    const forbidden = [
      '_importKeyForTesting',
      '_encryptChunkWithIV',
      '_internals',
      'InvocationCounter',
      'randomBytes',
      '_dh',
      '_extractAndExpand',
      '_combiner',
      '_keySchedule',
      'sealBase',
      'openBase',
      'extract',
      'expand',
      'labeledExtract',
      'labeledExpand',
      'concat',
      'i2osp',
      // Shamir internals
      'generateShares',
      'reconstructSecret',
      'P',
      'mod',
      'add',
      'sub',
      'mul',
      'inv',
      'pow',
      'bytesToBigInt',
      'bigIntToBytes',
      // ML-DSA internals
      'ml_dsa65',
      'ALGORITHM_ID',
      'PUBLIC_KEY_BYTES',
      'SECRET_KEY_BYTES',
      'SIGNATURE_BYTES',
      // Shard encryption internals
      'serializeShard',
      'deserializeShard',
      'SERIALIZED_SHARD_BYTES',
      'SHARD_VALUE_BYTES',
      'SHARD_MAC_BYTES',
    ];
    for (const name of forbidden) {
      expect(Object.keys(api)).not.toContain(name);
    }
  });
});
