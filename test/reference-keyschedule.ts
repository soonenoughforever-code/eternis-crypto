/**
 * Independent HPKE key schedule reference implementation.
 * Uses @noble/hashes (pure JS HMAC-SHA-256) — NOT our Web Crypto hkdf.ts.
 * Used to cross-validate our implementation for cipher suites without
 * published test vectors.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

const HASH_LENGTH = 32;

function refConcat(...arrays: Uint8Array[]): Uint8Array {
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

function refI2osp(value: number, length: number): Uint8Array {
  const result = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    result[i] = v & 0xff;
    v >>>= 8;
  }
  return result;
}

function refExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  const s = salt.length > 0 ? salt : new Uint8Array(HASH_LENGTH);
  return hmac(sha256, s, ikm);
}

function refExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const n = Math.ceil(length / HASH_LENGTH);
  const okm = new Uint8Array(n * HASH_LENGTH);
  let prev = new Uint8Array(0);
  for (let i = 1; i <= n; i++) {
    prev = hmac(sha256, prk, refConcat(prev, info, new Uint8Array([i])));
    okm.set(prev, (i - 1) * HASH_LENGTH);
  }
  return okm.slice(0, length);
}

const HPKE_V1 = new TextEncoder().encode('HPKE-v1');

function refLabeledExtract(
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array,
  suiteId: Uint8Array,
): Uint8Array {
  const labelBytes = new TextEncoder().encode(label);
  const labeledIkm = refConcat(HPKE_V1, suiteId, labelBytes, ikm);
  return refExtract(salt, labeledIkm);
}

function refLabeledExpand(
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
  suiteId: Uint8Array,
): Uint8Array {
  const labelBytes = new TextEncoder().encode(label);
  const labeledInfo = refConcat(refI2osp(length, 2), HPKE_V1, suiteId, labelBytes, info);
  return refExpand(prk, labeledInfo, length);
}

export interface RefKeyScheduleResult {
  key: Uint8Array;
  baseNonce: Uint8Array;
  pskIdHash: Uint8Array;
  infoHash: Uint8Array;
  ksContext: Uint8Array;
  secret: Uint8Array;
}

/**
 * Reference HPKE key schedule (RFC 9180 Section 5.1, Base mode).
 * All intermediate values are returned for thorough validation.
 */
export function refKeySchedule(
  mode: number,
  sharedSecret: Uint8Array,
  info: Uint8Array,
  suiteId: Uint8Array,
  nk: number,
  nn: number,
): RefKeyScheduleResult {
  const pskIdHash = refLabeledExtract(new Uint8Array(0), 'psk_id_hash', new Uint8Array(0), suiteId);
  const infoHash = refLabeledExtract(new Uint8Array(0), 'info_hash', info, suiteId);
  const ksContext = refConcat(new Uint8Array([mode]), pskIdHash, infoHash);
  const secret = refLabeledExtract(sharedSecret, 'secret', new Uint8Array(0), suiteId);
  const key = refLabeledExpand(secret, 'key', ksContext, nk, suiteId);
  const baseNonce = refLabeledExpand(secret, 'base_nonce', ksContext, nn, suiteId);
  return { key, baseNonce, pskIdHash, infoHash, ksContext, secret };
}

/** Helper to build HPKE suite_id. */
export function buildRefSuiteId(kemId: number, kdfId: number, aeadId: number): Uint8Array {
  const prefix = new TextEncoder().encode('HPKE');
  return refConcat(prefix, refI2osp(kemId, 2), refI2osp(kdfId, 2), refI2osp(aeadId, 2));
}
