import { InvocationCounter } from './internal/invocation-counter.js';

/**
 * Per-key ceiling. NIST SP 800-38D §8.3: a key generated with random IVs
 * must not exceed 2^32 invocations (IV collision probability ≤ 2^-32).
 */
const MAX_INVOCATIONS = 4_294_967_296 as const;

interface KeyHandleInternals {
  cryptoKey: CryptoKey;
  counter: InvocationCounter;
}

/**
 * Module-private bindings between public KeyHandle objects and their
 * underlying CryptoKey + counter. A WeakMap ensures the CryptoKey is
 * unreachable from outside this module and is GC'd with the handle.
 */
const internalBindings = new WeakMap<KeyHandle, KeyHandleInternals>();

/**
 * Opaque handle to a 256-bit AES key. The underlying CryptoKey is stored
 * with extractable=false, and its raw bytes are never exposed through
 * this handle. Callers see only algorithm metadata and the current
 * invocation count.
 */
export class KeyHandle {
  readonly algorithm = 'AES-256-GCM' as const;
  readonly maxInvocations = MAX_INVOCATIONS;

  /** @internal — do not construct directly. Use generateKey(). */
  constructor() {
    // Backing data is attached via internalBindings in the factory functions below.
  }

  get invocations(): number {
    const inner = internalBindings.get(this);
    if (!inner) throw new Error('KeyHandle: internal bindings missing (was this constructed via generateKey?)');
    return inner.counter.value;
  }
}

/**
 * Module-private accessor used by src/aes-gcm.ts. Not re-exported from
 * src/index.ts, so consumers of the public API cannot reach the CryptoKey.
 */
export function _internals(handle: KeyHandle): KeyHandleInternals {
  const inner = internalBindings.get(handle);
  if (!inner) {
    throw new Error('KeyHandle: internal bindings missing (was this constructed via generateKey?)');
  }
  return inner;
}

/**
 * Generate a fresh AES-256 key with extractable=false. The raw bytes
 * never leave the Web Crypto subsystem.
 */
export async function generateKey(): Promise<KeyHandle> {
  const cryptoKey = await globalThis.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const handle = new KeyHandle();
  internalBindings.set(handle, {
    cryptoKey,
    counter: new InvocationCounter(MAX_INVOCATIONS),
  });
  return handle;
}

/**
 * Test-only: import a raw 32-byte AES key for use against NIST CAVP
 * test vectors. Not re-exported from src/index.ts. Production code
 * must never call this.
 */
export async function _importKeyForTesting(rawKey: Uint8Array): Promise<KeyHandle> {
  if (rawKey.length !== 32) {
    throw new Error(`AES-256 key must be exactly 32 bytes, got ${String(rawKey.length)}`);
  }
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    rawKey as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const handle = new KeyHandle();
  internalBindings.set(handle, {
    cryptoKey,
    counter: new InvocationCounter(MAX_INVOCATIONS),
  });
  return handle;
}
