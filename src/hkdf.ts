const HASH = 'SHA-256' as const;
const HASH_LENGTH = 32;

/** Concatenate multiple Uint8Arrays into one. */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

/** Encode a non-negative integer as a big-endian byte string of the given length. */
export function i2osp(value: number, length: number): Uint8Array {
  const result = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    result[i] = v & 0xff;
    v >>>= 8;
  }
  return result;
}

async function importHmacKey(keyMaterial: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'raw',
    keyMaterial as Uint8Array<ArrayBuffer>,
    { name: 'HMAC', hash: HASH },
    false,
    ['sign'],
  );
}

/**
 * HKDF-Extract (RFC 5869 Section 2.2).
 * PRK = HMAC-SHA-256(salt, IKM)
 */
export async function extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  const key = await importHmacKey(salt.length > 0 ? salt : new Uint8Array(HASH_LENGTH));
  return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, ikm as Uint8Array<ArrayBuffer>));
}

/**
 * HKDF-Expand (RFC 5869 Section 2.3).
 * OKM = T(1) || T(2) || ... where T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i)
 */
export async function expand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const n = Math.ceil(length / HASH_LENGTH);
  const okm = new Uint8Array(n * HASH_LENGTH);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = concat(prev, info, new Uint8Array([i]));
    const key = await importHmacKey(prk);
    prev = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, input as Uint8Array<ArrayBuffer>));
    okm.set(prev, (i - 1) * HASH_LENGTH);
  }

  return okm.slice(0, length);
}

const HPKE_VERSION = new TextEncoder().encode('HPKE-v1');

/**
 * RFC 9180 Section 4 — LabeledExtract.
 * labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
 * return Extract(salt, labeled_ikm)
 */
export async function labeledExtract(
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array,
  suiteId: Uint8Array,
): Promise<Uint8Array> {
  const labelBytes = new TextEncoder().encode(label);
  const labeledIkm = concat(HPKE_VERSION, suiteId, labelBytes, ikm);
  return extract(salt, labeledIkm);
}

/**
 * RFC 9180 Section 4 — LabeledExpand.
 * labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
 * return Expand(prk, labeled_info, L)
 */
export async function labeledExpand(
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
  suiteId: Uint8Array,
): Promise<Uint8Array> {
  const labelBytes = new TextEncoder().encode(label);
  const labeledInfo = concat(i2osp(length, 2), HPKE_VERSION, suiteId, labelBytes, info);
  return expand(prk, labeledInfo, length);
}
