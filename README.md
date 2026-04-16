# eternis-crypto

Audited cryptographic primitives for [Eternis](https://eternis.co) — client-side encryption for long-horizon genomic data storage.

**Version:** 0.1.0
**Audit status:** NOT YET AUDITED by an external cryptographer. Private repo, pre-release. Do not depend on this.
**Runtime:** browsers + Node.js >= 22 (both expose Web Crypto).

## What this is

A minimal TypeScript wrapper over the Web Crypto API's AES-256-GCM implementation. Zero runtime dependencies. Validated against every NIST CAVP AES-256 GCM test vector (`gcmEncryptExtIV256.rsp` + `gcmDecrypt256.rsp`).

## Quick start

```ts
import { generateKey, encryptChunk, decryptChunk } from 'eternis-crypto';

const key = await generateKey();
const plaintext = new TextEncoder().encode('hello');
const aad = new Uint8Array(0);

const ct = await encryptChunk(key, plaintext, aad);
// ct = { iv: Uint8Array(12), ciphertext: Uint8Array, tag: Uint8Array(16) }

const recovered = await decryptChunk(key, ct, aad);
// new TextDecoder().decode(recovered) === 'hello'
```

## Three architectural principles (non-negotiable)

1. **IVs are always generated internally.** `encryptChunk` never accepts an IV parameter. This structurally prevents the GCM forbidden attack (Joux, nonce reuse).
2. **128-bit tags, always.** Truncated tags are out of scope for this library.
3. **AAD is an explicit required parameter.** Callers must pass `new Uint8Array(0)` to opt out of AAD. No implicit default — forces callers to think about context binding.

## API

### `generateKey(): Promise<KeyHandle>`

Generates a fresh AES-256 key with `extractable: false`. The raw bytes never leave the Web Crypto subsystem. The returned `KeyHandle` exposes only algorithm metadata and an invocation counter.

### `encryptChunk(key, plaintext, associatedData): Promise<Ciphertext>`

Encrypts a chunk. Generates a fresh random 96-bit IV. Returns `{ iv, ciphertext, tag }` — all three are required to decrypt.

- `plaintext` must be non-empty and <= 2^36 - 32 bytes.
- `associatedData` must be <= 1 MiB. Pass `new Uint8Array(0)` if not using AAD.
- Throws `KeyExhaustedError` at the 2^32 invocation ceiling.
- Throws `InvalidInputError` on size violations or empty plaintext.

### `decryptChunk(key, ciphertext, associatedData): Promise<Uint8Array>`

Decrypts. Returns the recovered plaintext.

- Throws `AuthenticationError` on any tag mismatch (wrong key, wrong AAD, tampered ciphertext, or tampered IV).
- Throws `InvalidInputError` on wrong-length IV or tag, or oversize AAD.
- Does NOT increment the invocation counter.

### Errors

- `EternisCryptoError` — base class.
- `AuthenticationError` — GCM tag mismatch.
- `KeyExhaustedError` — key reached 2^32 invocations.
- `InvalidInputError` — size or format violation.

## Security properties

**Claimed (conditional on Web Crypto's correctness):**
- IND-CPA + INT-CTXT (standard AEAD).
- Per-key lifetime bounded by 2^32 invocations per SP 800-38D section 8.3.
- No secret-dependent branches in wrapper code.

**NOT claimed:**
- **Replay protection.** Identical (iv, ciphertext, tag) tuples are indistinguishable on re-submission. Bind ciphertexts to sequence IDs or session IDs via AAD.
- **Post-quantum confidentiality.** AES-256 has ~128-bit post-quantum security under Grover (acceptable, not conservative). Post-quantum properties come from the key-exchange layer, handled elsewhere.
- **Forward secrecy.** Key compromise decrypts all past ciphertexts. Rotation is the caller's responsibility (separate future module).

## Validation

Every test vector in the NIST CAVP files below passes.

- `vectors/gcmEncryptExtIV256.rsp`
- `vectors/gcmDecrypt256.rsp`

Source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes

Re-run the validation:

```bash
npm test
```

## Development

```bash
npm install
npm run typecheck
npm run lint
npm test
npm run build    # emits dist/
```

## Audit and disclosure

This library has NOT yet been audited by an external cryptographer. Do not ship it to users. The repo will be flipped from private to public after the first external audit; a SECURITY.md with disclosure contact will be added at that time.

## License

MIT — see LICENSE.
