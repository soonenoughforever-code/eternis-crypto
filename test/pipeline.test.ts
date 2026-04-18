import { describe, expect, it } from 'vitest';
import { preserve, recover } from '../src/pipeline.js';
import { generateSigningKeyPair } from '../src/sig/ml-dsa.js';
import { HYBRID_X25519_MLKEM768 } from '../src/kem/hybrid-kem.js';
import type { PreservationPackage } from '../src/types.js';

async function generateCustodianKeyPairs(count: number) {
  const pairs = [];
  for (let i = 0; i < count; i++) {
    const kp = await HYBRID_X25519_MLKEM768.generateKeyPair();
    pairs.push(kp);
  }
  return pairs;
}

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

    expect(pkg.metadata.version).toBe('0.5.0');
    expect(pkg.metadata.threshold).toBe(3);
    expect(pkg.metadata.totalShards).toBe(5);
    expect(pkg.metadata.kemId).toBe('Hybrid-X25519-MLKEM768');
    expect(pkg.metadata.sigAlgorithmId).toBe('ML-DSA-65');
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
