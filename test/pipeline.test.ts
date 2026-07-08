import { describe, expect, it } from 'vitest';
import { preserve, recover, _drawInFieldSecret, recoverShardAt, openPreserved } from '../src/pipeline.js';
import { generateSigningKeyPair } from '../src/sig/ml-dsa.js';
import { HYBRID_X25519_MLKEM768 } from '../src/kem/hybrid-kem.js';
import type { PreservationPackage } from '../src/types.js';
import { AuthenticationError, InvalidInputError } from '../src/errors.js';
import { P, bytesToBigInt, bigIntToBytes } from '../src/sss/field.js';

async function generateCustodianKeyPairs(count: number) {
  const pairs = [];
  for (let i = 0; i < count; i++) {
    const kp = await HYBRID_X25519_MLKEM768.generateKeyPair();
    pairs.push(kp);
  }
  return pairs;
}

describe('DEK field-range sampling (F3)', () => {
  it('_drawInFieldSecret rejection-samples until the value is in [0, P)', () => {
    const outOfField = bigIntToBytes(P); // value == P -> must be rejected
    const inField = bigIntToBytes(P - 1n); // value == P-1 -> accepted
    const queue = [outOfField, inField];
    let calls = 0;
    const draw = (_n: number): Uint8Array => {
      calls++;
      return queue.shift()!;
    };
    const result = _drawInFieldSecret(draw);
    expect(calls).toBe(2); // redrew exactly once
    expect(bytesToBigInt(result) < P).toBe(true);
    expect(Array.from(result)).toEqual(Array.from(inField));
  });

  it('_drawInFieldSecret returns an in-field value from the real CSPRNG', () => {
    const result = _drawInFieldSecret();
    expect(result.length).toBe(32);
    expect(bytesToBigInt(result) < P).toBe(true);
  });
});

describe('preservation pipeline', () => {
  it('round-trips: preserve then recover returns original data', async () => {
    const data = new TextEncoder().encode('genomic data for 50-year preservation');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(5);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);

    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey);

    // Recover with first 3 custodians (threshold = 3)
    const custodianPrivateKeys = [
      { index: 0, privateKey: custodians[0]!.privateKey },
      { index: 1, privateKey: custodians[1]!.privateKey },
      { index: 2, privateKey: custodians[2]!.privateKey },
    ];

    const recovered = await recover(pkg, custodianPrivateKeys, sigKp.publicKey);
    expect(recovered).toEqual(data);
  });

  it('works with custom threshold (2-of-3)', async () => {
    const data = new TextEncoder().encode('custom threshold test');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);

    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey, {
      threshold: 2,
    });

    expect(pkg.metadata.threshold).toBe(2);
    expect(pkg.metadata.totalShards).toBe(3);

    const custodianPrivateKeys = [
      { index: 0, privateKey: custodians[0]!.privateKey },
      { index: 2, privateKey: custodians[2]!.privateKey },
    ];

    const recovered = await recover(pkg, custodianPrivateKeys, sigKp.publicKey);
    expect(recovered).toEqual(data);
  });

  it('works with DHKEM-X25519 KEM', async () => {
    const { DHKEM_X25519 } = await import('../src/kem/dhkem-x25519.js');
    const data = new TextEncoder().encode('dhkem test');
    const sigKp = generateSigningKeyPair();

    const custodians = [];
    for (let i = 0; i < 3; i++) {
      custodians.push(await DHKEM_X25519.generateKeyPair());
    }
    const custodianPublicKeys = custodians.map((c) => c.publicKey);

    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey, {
      threshold: 2,
      kem: DHKEM_X25519,
    });

    expect(pkg.metadata.kemId).toBe('DHKEM-X25519-HKDF-SHA256');

    const custodianPrivateKeys = [
      { index: 0, privateKey: custodians[0]!.privateKey },
      { index: 1, privateKey: custodians[1]!.privateKey },
    ];

    const recovered = await recover(pkg, custodianPrivateKeys, sigKp.publicKey, {
      kem: DHKEM_X25519,
    });
    expect(recovered).toEqual(data);
  });

  it('handles large data (1MB)', async () => {
    const data = new Uint8Array(1_048_576);
    for (let offset = 0; offset < data.length; offset += 65536) {
      globalThis.crypto.getRandomValues(data.subarray(offset, offset + 65536));
    }
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(5);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);

    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey);

    const custodianPrivateKeys = [
      { index: 1, privateKey: custodians[1]!.privateKey },
      { index: 3, privateKey: custodians[3]!.privateKey },
      { index: 4, privateKey: custodians[4]!.privateKey },
    ];

    const recovered = await recover(pkg, custodianPrivateKeys, sigKp.publicKey);
    expect(recovered).toEqual(data);
  });

  it('returns correct metadata', async () => {
    const data = new TextEncoder().encode('metadata test');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(5);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);

    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey);

    expect(pkg.metadata.version).toBe('0.6.0');
    expect(pkg.metadata.threshold).toBe(3);
    expect(pkg.metadata.totalShards).toBe(5);
    expect(pkg.metadata.kemId).toBe('Hybrid-X25519-MLKEM768');
    expect(pkg.metadata.sigAlgorithmId).toBe('ML-DSA-65');
    // F6/F8: a random per-package id must be present (32 lowercase-hex chars = 16 bytes)
    expect(pkg.metadata.packageId).toMatch(/^[0-9a-f]{32}$/);
    expect(pkg.encryptedShards).toHaveLength(5);
  });

  it('recovers with exactly threshold shards (boundary)', async () => {
    const data = new TextEncoder().encode('threshold boundary');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(5);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);

    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey);

    const custodianPrivateKeys = [
      { index: 2, privateKey: custodians[2]!.privateKey },
      { index: 3, privateKey: custodians[3]!.privateKey },
      { index: 4, privateKey: custodians[4]!.privateKey },
    ];

    const recovered = await recover(pkg, custodianPrivateKeys, sigKp.publicKey);
    expect(recovered).toEqual(data);
  });
});

describe('tampering detection', () => {
  async function createTestPackage() {
    const data = new TextEncoder().encode('tamper test data');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);
    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey, {
      threshold: 2,
    });
    return { pkg, sigKp, custodians };
  }

  it('detects tampered ciphertext', async () => {
    const { pkg, sigKp, custodians } = await createTestPackage();

    const tampered = new Uint8Array(pkg.encryptedData.ciphertext);
    tampered[0] = tampered[0]! ^ 0x01;

    const tamperedPkg: PreservationPackage = {
      ...pkg,
      encryptedData: { ...pkg.encryptedData, ciphertext: tampered },
    };

    const custodianPrivateKeys = [
      { index: 0, privateKey: custodians[0]!.privateKey },
      { index: 1, privateKey: custodians[1]!.privateKey },
    ];

    await expect(
      recover(tamperedPkg, custodianPrivateKeys, sigKp.publicKey),
    ).rejects.toThrow();
  });

  it('detects tampered authentication tag', async () => {
    const { pkg, sigKp, custodians } = await createTestPackage();

    const tampered = new Uint8Array(pkg.encryptedData.tag);
    tampered[0] = tampered[0]! ^ 0x01;

    const tamperedPkg: PreservationPackage = {
      ...pkg,
      encryptedData: { ...pkg.encryptedData, tag: tampered },
    };

    const custodianPrivateKeys = [
      { index: 0, privateKey: custodians[0]!.privateKey },
      { index: 1, privateKey: custodians[1]!.privateKey },
    ];

    await expect(
      recover(tamperedPkg, custodianPrivateKeys, sigKp.publicKey),
    ).rejects.toThrow();
  });

  it('detects tampered encrypted shard', async () => {
    const { pkg, sigKp, custodians } = await createTestPackage();

    const tamperedShards = [...pkg.encryptedShards];
    const tamperedCt = new Uint8Array(tamperedShards[0]!.ciphertext);
    tamperedCt[0] = tamperedCt[0]! ^ 0x01;
    tamperedShards[0] = { ...tamperedShards[0]!, ciphertext: tamperedCt };

    const tamperedPkg: PreservationPackage = {
      ...pkg,
      encryptedShards: tamperedShards,
    };

    const custodianPrivateKeys = [
      { index: 0, privateKey: custodians[0]!.privateKey },
      { index: 1, privateKey: custodians[1]!.privateKey },
    ];

    await expect(
      recover(tamperedPkg, custodianPrivateKeys, sigKp.publicKey),
    ).rejects.toThrow();
  });
});

describe('shard + metadata binding (F6/F8)', () => {
  // F8: metadata is authenticated by binding it into the data AEAD's AAD, so
  // editing any metadata field is detected on recover instead of trusted.
  it('detects tampered metadata.version (AAD binding of the data ciphertext)', async () => {
    const data = new TextEncoder().encode('metadata-binding test');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const pkg = await preserve(data, custodians.map((c) => c.publicKey), sigKp.secretKey, {
      threshold: 2,
    });
    const keys = [
      { index: 0, privateKey: custodians[0]!.privateKey },
      { index: 1, privateKey: custodians[1]!.privateKey },
    ];
    const tampered: PreservationPackage = {
      ...pkg,
      metadata: { ...pkg.metadata, version: '9.9.9' },
    };
    await expect(recover(tampered, keys, sigKp.publicKey)).rejects.toThrow(AuthenticationError);
  });

  it('detects tampered metadata.packageId (shard info + AAD binding)', async () => {
    const data = new TextEncoder().encode('packageId-binding test');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const pkg = await preserve(data, custodians.map((c) => c.publicKey), sigKp.secretKey, {
      threshold: 2,
    });
    const keys = [
      { index: 0, privateKey: custodians[0]!.privateKey },
      { index: 1, privateKey: custodians[1]!.privateKey },
    ];
    // flip one hex nibble of the package id
    const pid = pkg.metadata.packageId;
    const flipped = (pid[0] === '0' ? '1' : '0') + pid.slice(1);
    const tampered: PreservationPackage = {
      ...pkg,
      metadata: { ...pkg.metadata, packageId: flipped },
    };
    await expect(recover(tampered, keys, sigKp.publicKey)).rejects.toThrow(AuthenticationError);
  });

  // F6: a shard is bound (via HPKE info) to its package + slot, so a validly
  // signed shard replayed from ANOTHER package to the SAME custodian is rejected
  // EARLY at HPKE decryption (AuthenticationError), not late at the HMAC.
  it('rejects a cross-package shard replay early (HPKE bind, not late HMAC)', async () => {
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const pubs = custodians.map((c) => c.publicKey);

    const pkgA = await preserve(new TextEncoder().encode('package A'), pubs, sigKp.secretKey, {
      threshold: 2,
    });
    const pkgB = await preserve(new TextEncoder().encode('package B'), pubs, sigKp.secretKey, {
      threshold: 2,
    });

    // Splice package B's slot-0 shard (sealed to the same custodian 0) into A.
    const spliced: PreservationPackage = {
      ...pkgA,
      encryptedShards: [pkgB.encryptedShards[0]!, ...pkgA.encryptedShards.slice(1)],
    };
    const keys = [
      { index: 0, privateKey: custodians[0]!.privateKey },
      { index: 1, privateKey: custodians[1]!.privateKey },
    ];
    await expect(recover(spliced, keys, sigKp.publicKey)).rejects.toThrow(AuthenticationError);
  });
});

describe('input validation', () => {
  it('preserve rejects empty data', async () => {
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);

    await expect(
      preserve(new Uint8Array(0), custodianPublicKeys, sigKp.secretKey, { threshold: 2 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('preserve rejects fewer custodian keys than threshold', async () => {
    const data = new TextEncoder().encode('test');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(2);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);

    await expect(
      preserve(data, custodianPublicKeys, sigKp.secretKey, { threshold: 3 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('preserve rejects invalid signing key', async () => {
    const data = new TextEncoder().encode('test');
    const custodians = await generateCustodianKeyPairs(3);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);

    await expect(
      preserve(data, custodianPublicKeys, new Uint8Array(32), { threshold: 2 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('recover rejects fewer keys than threshold', async () => {
    const data = new TextEncoder().encode('test');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);
    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey, {
      threshold: 2,
    });

    await expect(
      recover(pkg, [{ index: 0, privateKey: custodians[0]!.privateKey }], sigKp.publicKey),
    ).rejects.toThrow(InvalidInputError);
  });

  it('recover rejects invalid shard index', async () => {
    const data = new TextEncoder().encode('test');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);
    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey, {
      threshold: 2,
    });

    await expect(
      recover(pkg, [
        { index: 0, privateKey: custodians[0]!.privateKey },
        { index: 99, privateKey: custodians[1]!.privateKey },
      ], sigKp.publicKey),
    ).rejects.toThrow(InvalidInputError);
  });

  it('recover fails with wrong custodian key', async () => {
    const data = new TextEncoder().encode('wrong key test');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);
    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey, {
      threshold: 2,
    });

    const wrongCustodian = await HYBRID_X25519_MLKEM768.generateKeyPair();

    await expect(
      recover(pkg, [
        { index: 0, privateKey: wrongCustodian.privateKey },
        { index: 1, privateKey: custodians[1]!.privateKey },
      ], sigKp.publicKey),
    ).rejects.toThrow();
  });

  it('recover fails with wrong owner verify key', async () => {
    const data = new TextEncoder().encode('wrong verify key');
    const sigKp = generateSigningKeyPair();
    const wrongSigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(3);
    const custodianPublicKeys = custodians.map((c) => c.publicKey);
    const pkg = await preserve(data, custodianPublicKeys, sigKp.secretKey, {
      threshold: 2,
    });

    await expect(
      recover(pkg, [
        { index: 0, privateKey: custodians[0]!.privateKey },
        { index: 1, privateKey: custodians[1]!.privateKey },
      ], wrongSigKp.publicKey),
    ).rejects.toThrow();
  });
});

describe('decomposed recovery API (v0.6.1)', () => {
  it('recoverShardAt decrypts a single shard with the correct per-slot binding', async () => {
    const data = new TextEncoder().encode('master key material for decomposed recovery');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(5);
    const pkg = await preserve(data, custodians.map((c) => c.publicKey), sigKp.secretKey, {
      threshold: 3,
    });
    const shard = await recoverShardAt(pkg, 2, custodians[2]!.privateKey, sigKp.publicKey);
    expect(shard.index).toBe(3);          // slot 2 -> Shamir index 3
    expect(shard.value.length).toBe(32);
    expect(shard.mac.length).toBe(32);
  });

  it('recoverShardAt throws for an out-of-range slot', async () => {
    const data = new TextEncoder().encode('x');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(5);
    const pkg = await preserve(data, custodians.map((c) => c.publicKey), sigKp.secretKey, {
      threshold: 3,
    });
    await expect(
      recoverShardAt(pkg, 9, custodians[0]!.privateKey, sigKp.publicKey),
    ).rejects.toThrow(InvalidInputError);
  });

  it('openPreserved reconstructs the data from any 3 recovered shards', async () => {
    const data = new TextEncoder().encode('decomposed-recovery round trip payload');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(5);
    const pkg = await preserve(data, custodians.map((c) => c.publicKey), sigKp.secretKey, {
      threshold: 3,
    });
    // mixed subset: slots 1, 2, 3
    const shards = await Promise.all(
      [1, 2, 3].map((slot) => recoverShardAt(pkg, slot, custodians[slot]!.privateKey, sigKp.publicKey)),
    );
    const recovered = await openPreserved(pkg, shards);
    expect(recovered).toEqual(data);
  });

  it('openPreserved rejects fewer than threshold shards', async () => {
    const data = new TextEncoder().encode('threshold guard');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(5);
    const pkg = await preserve(data, custodians.map((c) => c.publicKey), sigKp.secretKey, {
      threshold: 3,
    });
    const two = await Promise.all(
      [0, 1].map((slot) => recoverShardAt(pkg, slot, custodians[slot]!.privateKey, sigKp.publicKey)),
    );
    await expect(openPreserved(pkg, two)).rejects.toThrow(InvalidInputError);
  });

  it('openPreserved rejects duplicate Shamir indexes', async () => {
    const data = new TextEncoder().encode('dup guard');
    const sigKp = generateSigningKeyPair();
    const custodians = await generateCustodianKeyPairs(5);
    const pkg = await preserve(data, custodians.map((c) => c.publicKey), sigKp.secretKey, {
      threshold: 3,
    });
    const s0 = await recoverShardAt(pkg, 0, custodians[0]!.privateKey, sigKp.publicKey);
    const s1 = await recoverShardAt(pkg, 1, custodians[1]!.privateKey, sigKp.publicKey);
    await expect(openPreserved(pkg, [s0, s1, s0])).rejects.toThrow(InvalidInputError);
  });
});
