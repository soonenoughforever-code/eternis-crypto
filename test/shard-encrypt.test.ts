import { describe, expect, it } from 'vitest';
import { distributeShard, recoverShard } from '../src/sss/shard-encrypt.js';
import { splitKey } from '../src/sss/key-split.js';
import { combineShards } from '../src/sss/key-split.js';
import { generateSigningKeyPair } from '../src/sig/ml-dsa.js';
import { generateMasterKeyPair } from '../src/key-wrap.js';
import { DHKEM_X25519 } from '../src/kem/dhkem-x25519.js';
import {
  AuthenticationError,
  InvalidInputError,
  SignatureVerificationError,
} from '../src/errors.js';

describe('distributeShard + recoverShard round-trip', () => {
  it('full round-trip: splitKey → distribute → recover → combineShards', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 3, shares: 5 });

    const ownerSig = generateSigningKeyPair();

    // Encrypt each shard for a different custodian
    const custodians = await Promise.all(
      shards.map(() => generateMasterKeyPair()),
    );

    const encrypted = await Promise.all(
      shards.map((shard, i) =>
        distributeShard(shard, custodians[i]!.publicKey, ownerSig.secretKey),
      ),
    );

    // Recover 3 of 5
    const recovered = await Promise.all(
      [0, 2, 4].map((i) =>
        recoverShard(encrypted[i]!, custodians[i]!.privateKey, ownerSig.publicKey),
      ),
    );

    const result = await combineShards(recovered);
    expect(Array.from(result)).toEqual(Array.from(secret));
  });

  it('round-trip with DHKEM-X25519', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );
    expect(encrypted.kemId).toBe('DHKEM-X25519-HKDF-SHA256');

    const recovered = await recoverShard(
      encrypted,
      custodian.privateKey,
      ownerSig.publicKey,
      { kem: DHKEM_X25519 },
    );
    expect(recovered.index).toBe(shards[0]!.index);
    expect(Array.from(recovered.value)).toEqual(Array.from(shards[0]!.value));
    expect(Array.from(recovered.mac)).toEqual(Array.from(shards[0]!.mac));
  });

  it('round-trip with HPKE info parameter', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);
    const info = new TextEncoder().encode('sample-id-001');

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519, info },
    );

    const recovered = await recoverShard(
      encrypted,
      custodian.privateKey,
      ownerSig.publicKey,
      { kem: DHKEM_X25519, info },
    );
    expect(recovered.index).toBe(shards[0]!.index);
  });

  it('preserves shard integrity (index, value, mac)', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });
    const shard = shards[0]!;

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shard,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );
    const recovered = await recoverShard(
      encrypted,
      custodian.privateKey,
      ownerSig.publicKey,
      { kem: DHKEM_X25519 },
    );

    expect(recovered.index).toBe(shard.index);
    expect(Array.from(recovered.value)).toEqual(Array.from(shard.value));
    expect(Array.from(recovered.mac)).toEqual(Array.from(shard.mac));
  });

  it('different custodians get different encrypted shards', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const c1 = await generateMasterKeyPair(DHKEM_X25519);
    const c2 = await generateMasterKeyPair(DHKEM_X25519);

    const e1 = await distributeShard(
      shards[0]!,
      c1.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );
    const e2 = await distributeShard(
      shards[0]!,
      c2.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    expect(Array.from(e1.enc)).not.toEqual(Array.from(e2.enc));
  });
});

describe('recoverShard error cases', () => {
  it('wrong custodian private key throws AuthenticationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const c1 = await generateMasterKeyPair(DHKEM_X25519);
    const c2 = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      c1.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    await expect(
      recoverShard(encrypted, c2.privateKey, ownerSig.publicKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('wrong owner verify key throws SignatureVerificationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig1 = generateSigningKeyPair();
    const ownerSig2 = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig1.secretKey,
      { kem: DHKEM_X25519 },
    );

    await expect(
      recoverShard(encrypted, custodian.privateKey, ownerSig2.publicKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(SignatureVerificationError);
  });

  it('tampered ciphertext throws AuthenticationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    const tampered = new Uint8Array(encrypted.ciphertext);
    tampered[0] ^= 0x01;

    await expect(
      recoverShard(
        { ...encrypted, ciphertext: tampered },
        custodian.privateKey,
        ownerSig.publicKey,
        { kem: DHKEM_X25519 },
      ),
    ).rejects.toThrow(AuthenticationError);
  });

  it('tampered enc throws AuthenticationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    const tampered = new Uint8Array(encrypted.enc);
    tampered[0] ^= 0x01;

    await expect(
      recoverShard(
        { ...encrypted, enc: tampered },
        custodian.privateKey,
        ownerSig.publicKey,
        { kem: DHKEM_X25519 },
      ),
    ).rejects.toThrow(AuthenticationError);
  });

  it('tampered tag throws AuthenticationError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    const tampered = new Uint8Array(encrypted.tag);
    tampered[0] ^= 0x01;

    await expect(
      recoverShard(
        { ...encrypted, tag: tampered },
        custodian.privateKey,
        ownerSig.publicKey,
        { kem: DHKEM_X25519 },
      ),
    ).rejects.toThrow(AuthenticationError);
  });

  it('KEM ID mismatch throws InvalidInputError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair();

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
    );

    // Try to recover with DHKEM-X25519 but encrypted with hybrid
    await expect(
      recoverShard(encrypted, custodian.privateKey, ownerSig.publicKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });
});

describe('distributeShard input validation', () => {
  it('invalid shard value size throws InvalidInputError', async () => {
    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const badShard = { index: 1, value: new Uint8Array(16), mac: new Uint8Array(32) };
    await expect(
      distributeShard(badShard, custodian.publicKey, ownerSig.secretKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('invalid shard mac size throws InvalidInputError', async () => {
    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const badShard = { index: 1, value: new Uint8Array(32), mac: new Uint8Array(16) };
    await expect(
      distributeShard(badShard, custodian.publicKey, ownerSig.secretKey, { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('invalid ownerSigningKey size throws InvalidInputError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    await expect(
      distributeShard(shards[0]!, custodian.publicKey, new Uint8Array(32), { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });

  it('invalid ownerVerifyKey size throws InvalidInputError', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shards } = await splitKey(secret, { threshold: 2, shares: 3 });

    const ownerSig = generateSigningKeyPair();
    const custodian = await generateMasterKeyPair(DHKEM_X25519);

    const encrypted = await distributeShard(
      shards[0]!,
      custodian.publicKey,
      ownerSig.secretKey,
      { kem: DHKEM_X25519 },
    );

    await expect(
      recoverShard(encrypted, custodian.privateKey, new Uint8Array(32), { kem: DHKEM_X25519 }),
    ).rejects.toThrow(InvalidInputError);
  });
});
