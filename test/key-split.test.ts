import { describe, expect, it } from 'vitest';
import { splitKey, combineShards } from '../src/sss/key-split.js';
import { InvalidInputError, ShardAuthenticationError } from '../src/errors.js';
import type { Shard } from '../src/types.js';

describe('splitKey + combineShards round-trip', () => {
  it('(3,5) round-trip', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });

    expect(result.shards.length).toBe(5);
    expect(result.threshold).toBe(3);

    const recovered = await combineShards(result.shards.slice(0, 3));
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('(2,3) round-trip', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 2, shares: 3 });
    const recovered = await combineShards([result.shards[0]!, result.shards[2]!]);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('(4,7) round-trip', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 4, shares: 7 });
    const recovered = await combineShards(result.shards.slice(0, 4));
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('(5,5) round-trip', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 5, shares: 5 });
    const recovered = await combineShards(result.shards);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('more than threshold shards also works', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    const recovered = await combineShards(result.shards);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });
});

describe('shard format', () => {
  it('each shard has index, 32-byte value, 32-byte mac', async () => {
    const secret = new Uint8Array(32).fill(0xab);
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    for (const shard of result.shards) {
      expect(typeof shard.index).toBe('number');
      expect(shard.index).toBeGreaterThanOrEqual(1);
      expect(shard.index).toBeLessThanOrEqual(5);
      expect(shard.value.length).toBe(32);
      expect(shard.mac.length).toBe(32);
    }
  });

  it('different splits produce different shards', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    const r1 = await splitKey(secret, { threshold: 3, shares: 5 });
    const r2 = await splitKey(secret, { threshold: 3, shares: 5 });
    const allSame = r1.shards.every(
      (s, i) => Array.from(s.value).join() === Array.from(r2.shards[i]!.value).join(),
    );
    expect(allSame).toBe(false);
  });
});

describe('tamper detection', () => {
  it('modified shard value throws ShardAuthenticationError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    const shards = result.shards.map((s) => ({ ...s }));
    const tampered = new Uint8Array(shards[0]!.value);
    tampered.set([tampered[0]! ^ 0x01], 0);
    shards[0] = { ...shards[0]!, value: tampered };
    await expect(combineShards(shards.slice(0, 3))).rejects.toThrow(ShardAuthenticationError);
  });

  it('modified shard MAC throws ShardAuthenticationError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    const shards = result.shards.map((s) => ({ ...s }));
    const tampered = new Uint8Array(shards[1]!.mac);
    tampered.set([tampered[0]! ^ 0x01], 0);
    shards[1] = { ...shards[1]!, mac: tampered };
    await expect(combineShards(shards.slice(0, 3))).rejects.toThrow(ShardAuthenticationError);
  });

  it('swapped MACs between shards throws ShardAuthenticationError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    const shards = result.shards.map((s) => ({ ...s }));
    // Swap MACs of shard 0 and shard 1
    const mac0 = shards[0]!.mac;
    shards[0] = { ...shards[0]!, mac: shards[1]!.mac };
    shards[1] = { ...shards[1]!, mac: mac0 };
    await expect(combineShards(shards.slice(0, 3))).rejects.toThrow(ShardAuthenticationError);
  });

  it('modified shard index throws ShardAuthenticationError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 3, shares: 5 });
    // Use shards 0,1,2 but change shard 0's index
    // This will cause wrong reconstruction AND MAC mismatch
    const shards: Shard[] = [
      { index: 99, value: result.shards[0]!.value, mac: result.shards[0]!.mac },
      result.shards[1]!,
      result.shards[2]!,
    ];
    await expect(combineShards(shards)).rejects.toThrow(ShardAuthenticationError);
  });
});

describe('splitKey validation', () => {
  it('secret not 32 bytes throws InvalidInputError', async () => {
    await expect(splitKey(new Uint8Array(16), { threshold: 2, shares: 3 })).rejects.toThrow(
      InvalidInputError,
    );
    await expect(splitKey(new Uint8Array(33), { threshold: 2, shares: 3 })).rejects.toThrow(
      InvalidInputError,
    );
    await expect(splitKey(new Uint8Array(0), { threshold: 2, shares: 3 })).rejects.toThrow(
      InvalidInputError,
    );
  });

  it('all-zero secret throws InvalidInputError', async () => {
    await expect(splitKey(new Uint8Array(32), { threshold: 2, shares: 3 })).rejects.toThrow(
      InvalidInputError,
    );
  });

  it('threshold < 2 throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 1, shares: 3 })).rejects.toThrow(InvalidInputError);
    await expect(splitKey(secret, { threshold: 0, shares: 3 })).rejects.toThrow(InvalidInputError);
  });

  it('shares < threshold throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 3, shares: 2 })).rejects.toThrow(InvalidInputError);
  });

  it('shares > 255 throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 2, shares: 256 })).rejects.toThrow(
      InvalidInputError,
    );
  });

  it('non-integer threshold throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 2.5, shares: 5 })).rejects.toThrow(
      InvalidInputError,
    );
  });

  it('non-integer shares throws InvalidInputError', async () => {
    const secret = new Uint8Array(32).fill(0x42);
    await expect(splitKey(secret, { threshold: 3, shares: 5.5 })).rejects.toThrow(
      InvalidInputError,
    );
  });
});

describe('combineShards validation', () => {
  it('fewer than 2 shards throws InvalidInputError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 2, shares: 3 });
    await expect(combineShards([result.shards[0]!])).rejects.toThrow(InvalidInputError);
    await expect(combineShards([])).rejects.toThrow(InvalidInputError);
  });

  it('duplicate indexes throw InvalidInputError', async () => {
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const result = await splitKey(secret, { threshold: 2, shares: 3 });
    const dup: Shard[] = [result.shards[0]!, result.shards[0]!];
    await expect(combineShards(dup)).rejects.toThrow(InvalidInputError);
  });

  it('shard value not 32 bytes throws InvalidInputError', async () => {
    const bad: Shard[] = [
      { index: 1, value: new Uint8Array(16), mac: new Uint8Array(32) },
      { index: 2, value: new Uint8Array(32), mac: new Uint8Array(32) },
    ];
    await expect(combineShards(bad)).rejects.toThrow(InvalidInputError);
  });

  it('shard MAC not 32 bytes throws InvalidInputError', async () => {
    const bad: Shard[] = [
      { index: 1, value: new Uint8Array(32), mac: new Uint8Array(16) },
      { index: 2, value: new Uint8Array(32), mac: new Uint8Array(32) },
    ];
    await expect(combineShards(bad)).rejects.toThrow(InvalidInputError);
  });
});
