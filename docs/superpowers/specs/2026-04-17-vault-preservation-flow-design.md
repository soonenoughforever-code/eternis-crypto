# Vault Genomic Preservation Flow — Design Spec

> **For agentic workers:** This is a design spec, not an implementation plan. Use superpowers:writing-plans to create the implementation plan from this spec.

**Date:** 2026-04-17
**Status:** Draft
**Scope:** Genomic data only. Digital Epigenome (social media archives) is explicitly out of scope for the crypto layer.

---

## 1. Problem Statement

Eternis preserves biological samples (DNA, stem cells) in cryogenic storage via its lab partner Sampled. The lab generates large genomic data files (FASTQ, BAM, VCF — up to 120 GB per file) that must be:

1. Encrypted end-to-end so that only the customer (or their designated beneficiaries) can ever decrypt them.
2. Stored durably with cryptographic proof of integrity.
3. Recoverable via a Shamir-based key custody model — no single party (including Eternis) can access the data alone.

The customer never touches raw genomic files. The lab produces them. The encryption must happen at the source.

## 2. Goals

- **End-to-end encryption:** Genomic data is encrypted before it leaves the lab. Eternis never sees plaintext.
- **Customer key custody:** Each customer's private key is Shamir-split at signup and erased. No single party holds the full key.
- **Integrity proof:** Customers can verify their data hasn't been tampered with, without decrypting it.
- **Trust Dashboard:** Customers see proof of preservation (encryption status, custodian list, integrity checks, activity log) — not a file browser.
- **Large file support:** Handle 60-120 GB BAM files via TUS resumable uploads directly to storage.

## 3. Non-Goals (MVP)

- **Option 2 (Eternis encrypts):** The `preserve()` function in eternis-crypto takes `Uint8Array`, which cannot hold 120 GB in memory. Streaming encryption is not yet built. MVP is Option 1 only (Sampled encrypts with Crypt4GH).
- **File browsing / download:** The Trust Dashboard shows proof of preservation, not file contents.
- **Decryption in the browser:** Decryption is a future feature tied to beneficiary access and clinical research sharing.
- **Genomic Passport tab:** Future phase.
- **Clinical research sharing:** Future phase.
- **Digital Epigenome encryption:** Out of scope for this crypto layer entirely.

## 4. Architecture Overview

### 4.1 Encryption Standard: GA4GH Crypt4GH

**Research basis:** GA4GH Crypt4GH file encryption standard (wiki/papers/ga4gh-2021-crypt4gh-file-encryption.md), Crypt4GH-JS browser implementation (wiki/papers/thelen-2025-crypt4gh-js.md).

Crypt4GH is the genomics industry standard for encrypting large files at rest. It uses:
- **X25519** key agreement (Curve25519 ECDH)
- **ChaCha20-IETF-Poly1305** authenticated encryption for data blocks
- **Envelope encryption:** A per-file symmetric Data Encryption Key (DEK) is generated, used to encrypt the file in 64 KiB blocks, then the DEK is encrypted with the recipient's X25519 public key in the file header.

This is the same standard used by the European Genome-phenome Archive (EGA) in production.

### 4.2 Key Lifecycle

**Research basis:** Shamir (1979) (wiki/papers/shamir-1979-how-to-share-a-secret.md), HashiCorp Vault seal/unseal (wiki/papers/hashicorp-2024-vault-shamir-seal.md), OWASP Key Management (wiki/papers/owasp-2024-key-management.md), Keybase paper keys (wiki/papers/keybase-2024-paper-keys.md).

```
Customer Signup
    │
    ▼
Generate X25519 key pair (browser, Web Crypto API)
    │
    ├── Public key → stored in `profiles.preservation_public_key`
    │                 Sent to Sampled for Crypt4GH encryption
    │
    └── Private key (32 bytes)
            │
            ▼
        Shamir split: 3-of-3 (initial)
            │
            ├── Shard 1 → Customer (encrypted, stored client-side or downloaded)
            ├── Shard 2 → Eternis Primary (encrypted, stored in `preservation_shards`)
            └── Shard 3 → Eternis Backup (encrypted, stored in `preservation_shards`)
            │
            ▼
        Private key securely erased from memory
```

**Per-customer, not per-file.** One X25519 key pair per customer. The 32-byte private key fits cleanly in Shamir's GF(p) field. All genomic files for a customer are encrypted with the same public key via Crypt4GH's envelope model (each file gets its own random DEK, but the DEK is always encrypted to the same public key). One key recovery unlocks everything.

**Why 3-of-3 initially:** At signup, there is no beneficiary. Starting with 3-of-5 would mean 2 "empty" custodian slots. Instead, start with 3-of-3 (all three parties required). When a beneficiary is designated, reshare to 3-of-5 using the proactive resharing primitive (on the eternis-crypto roadmap).

### 4.3 Data Flow: Lab-to-Vault Ingestion

**Research basis:** TUS resumable upload protocol (wiki/papers/tus-2024-resumable-upload-protocol.md), Crypt4GH spec.

Sampled (the lab) cannot POST 120 GB through a Next.js API route (Vercel has ~4 MB body limits). The ingestion uses a two-step presigned-URL flow:

```
Sampled                          Eternis API                    Supabase Storage
  │                                  │                               │
  │  POST /api/preservation/init     │                               │
  │  { sample_id, file_type,         │                               │
  │    file_size, plaintext_hash,    │                               │
  │    crypt4gh_header_b64 }         │                               │
  │ ──────────────────────────────►  │                               │
  │                                  │  Create DB record             │
  │                                  │  (status: uploading)          │
  │                                  │                               │
  │                                  │  Generate presigned TUS URL   │
  │                                  │  ─────────────────────────►   │
  │  ◄─────────────────────────────  │                               │
  │  { upload_url, upload_id }       │                               │
  │                                  │                               │
  │  TUS PATCH (6 MB chunks)         │                               │
  │ ─────────────────────────────────────────────────────────────►   │
  │  (resumable, 24-hour URL validity)                               │
  │                                  │                               │
  │  POST /api/preservation/complete │                               │
  │  { upload_id }                   │                               │
  │ ──────────────────────────────►  │                               │
  │                                  │  Compute ciphertext_hash      │
  │                                  │  Write final DB record        │
  │                                  │  (status: preserved)          │
  │                                  │                               │
  │  ◄─────────────────────────────  │                               │
  │  { status: preserved }           │                               │
```

**Authentication:** Sampled authenticates via HMAC-SHA256 request signing (industry standard pattern used by Stripe, GitHub, Shopify). Each request includes an `X-Signature-256` header containing `HMAC-SHA256(shared_secret, request_body)`. The API verifies using constant-time comparison (`crypto.timingSafeEqual`). A `X-Timestamp` header enables replay window enforcement (reject requests older than 5 minutes). This is stronger than a static API key — the shared secret is never transmitted, and each signature is tied to the specific request body.

**Research basis:** OWASP API Security Top 10 (wiki/papers/owasp-2023-api-security-top-10.md) — API keys authenticate clients, not users; use industry standards. Webhook HMAC Signature Verification (wiki/papers/webhooks-fyi-2024-hmac-signature-verification.md) — HMAC-SHA256 signing pattern.

### 4.4 Two-Hash Integrity Model

**Research basis:** OWASP Key Management (wiki/papers/owasp-2024-key-management.md).

| Hash | Computed by | When | Purpose |
|------|------------|------|---------|
| `plaintext_hash` | Sampled (before encryption) | At `/init` | Trusted record of original data integrity. Verifiable only upon decryption. |
| `ciphertext_hash` | Eternis (after upload) | At `/complete` | Verifiable anytime without decryption. Proves stored blob hasn't been tampered with. |

Both are SHA-256. The `ciphertext_hash` can be re-verified at any time by re-hashing the stored blob. The `plaintext_hash` can only be verified after decryption (future feature).

## 5. Data Model

### 5.1 Schema Changes

**Modify `profiles` table:**

```sql
ALTER TABLE profiles ADD COLUMN preservation_public_key TEXT;
-- Base64-encoded X25519 public key (32 bytes → 44 chars base64)
-- NULL until key ceremony at signup
```

**New `preservation_files` table:**

```sql
CREATE TABLE preservation_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id UUID REFERENCES profiles(id) NOT NULL,
  sample_id UUID REFERENCES samples(id),
  file_type TEXT NOT NULL CHECK (file_type IN ('fastq', 'bam', 'vcf', 'cram', 'other')),
  file_size BIGINT NOT NULL,
  storage_path TEXT NOT NULL,
  crypt4gh_header TEXT NOT NULL,        -- Base64-encoded Crypt4GH header
  plaintext_hash TEXT NOT NULL,         -- SHA-256 of plaintext (from Sampled)
  ciphertext_hash TEXT,                 -- SHA-256 of ciphertext (computed at /complete)
  status TEXT NOT NULL DEFAULT 'uploading'
    CHECK (status IN ('uploading', 'preserved', 'failed', 'verifying')),
  uploaded_by TEXT NOT NULL DEFAULT 'sampled',
  created_at TIMESTAMPTZ DEFAULT now(),
  verified_at TIMESTAMPTZ,
  upload_id TEXT UNIQUE                 -- TUS upload identifier
);

-- RLS: customers see only their own files' metadata (not the blob)
ALTER TABLE preservation_files ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users view own preservation files"
  ON preservation_files FOR SELECT
  USING (profile_id = auth.uid());
```

**New `preservation_shards` table:**

```sql
CREATE TABLE preservation_shards (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id UUID REFERENCES profiles(id) NOT NULL,
  custodian_type TEXT NOT NULL
    CHECK (custodian_type IN ('customer', 'eternis_primary', 'eternis_backup', 'beneficiary', 'trustee')),
  shard_index INTEGER NOT NULL,         -- Shamir share index (1-based)
  encrypted_shard TEXT NOT NULL,        -- Encrypted shard data (base64)
  encryption_method TEXT NOT NULL DEFAULT 'aes-256-gcm',
  created_at TIMESTAMPTZ DEFAULT now(),
  rotated_at TIMESTAMPTZ,
  UNIQUE (profile_id, shard_index)
);

-- RLS: customers see only their own shards
ALTER TABLE preservation_shards ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users view own shards"
  ON preservation_shards FOR SELECT
  USING (profile_id = auth.uid());
```

**New `preservation_custodians` table:**

```sql
CREATE TABLE preservation_custodians (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id UUID REFERENCES profiles(id) NOT NULL,
  custodian_type TEXT NOT NULL
    CHECK (custodian_type IN ('customer', 'eternis_primary', 'eternis_backup', 'beneficiary', 'trustee')),
  display_name TEXT NOT NULL,           -- "You", "Eternis Primary", beneficiary name
  holds_shard BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE preservation_custodians ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users view own custodians"
  ON preservation_custodians FOR SELECT
  USING (profile_id = auth.uid());
```

**New `preservation_activity_log` table:**

```sql
CREATE TABLE preservation_activity_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id UUID REFERENCES profiles(id) NOT NULL,
  event_type TEXT NOT NULL
    CHECK (event_type IN (
      'key_generated', 'key_split', 'file_uploaded', 'file_preserved',
      'integrity_verified', 'custodian_added', 'custodian_removed',
      'shard_rotated', 'access_requested'
    )),
  description TEXT NOT NULL,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE preservation_activity_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users view own activity"
  ON preservation_activity_log FOR SELECT
  USING (profile_id = auth.uid());
```

### 5.2 Storage

**Supabase Storage** (S3-backed, 11 nines durability) for MVP. Encrypted blobs stored in a `preservation` bucket with path pattern: `{profile_id}/{file_id}.c4gh`.

**Research basis:** Supabase implements TUS with fixed 6 MB chunks, 24-hour URL validity. Only one client can upload to the same URL at a time (prevents corruption). This is adequate for MVP. Migration to dedicated S3 or a genomics-specific storage service is a future consideration if needed.

## 6. API Routes

### 6.0 API-Wide Security

**Research basis:** OWASP API Security Top 10 (wiki/papers/owasp-2023-api-security-top-10.md).

All Sampled-facing endpoints (`/init`, `/complete`, `/public-key`) share these security measures:

- **HMAC-SHA256 request signing:** Shared secret pre-exchanged. Signature in `X-Signature-256` header. Constant-time verification via `crypto.timingSafeEqual`.
- **Replay window:** `X-Timestamp` header required. Reject requests older than 5 minutes.
- **Rate limiting:** Max 10 requests/minute per endpoint per API client. Stricter limits on `/public-key` (1 request/minute per sample_id) to prevent key enumeration.
- **Idempotency:** `/init` checks for existing `uploading` record for the same `sample_id` + `file_type` combination. Returns existing upload URL if found (prevents duplicate records from retried requests).

### 6.1 `POST /api/preservation/init`

**Purpose:** Sampled calls this to register a new file and get a presigned upload URL.

**Auth:** HMAC-SHA256 request signing (`X-Signature-256` + `X-Timestamp` headers).

**Request body:**
```json
{
  "sample_id": "uuid",
  "file_type": "bam",
  "file_size": 128849018880,
  "plaintext_hash": "sha256:abc123...",
  "crypt4gh_header_b64": "base64-encoded-header"
}
```

**Response:**
```json
{
  "upload_id": "uuid",
  "upload_url": "https://xxx.supabase.co/storage/v1/upload/resumable/...",
  "expires_at": "2026-04-18T19:00:00Z"
}
```

**Logic:**
1. Validate HMAC signature + timestamp (reject if >5 min old).
2. Look up `sample_id` → get `profile_id`.
3. Verify `profile_id` has a `preservation_public_key` (key ceremony completed).
4. Create `preservation_files` row with `status: 'uploading'`.
5. Generate presigned TUS upload URL via Supabase Storage API.
6. Log `file_uploaded` event to activity log.
7. Return upload URL and ID.

### 6.2 `POST /api/preservation/complete`

**Purpose:** Sampled calls this after TUS upload finishes.

**Auth:** HMAC-SHA256 request signing.

**Request body:**
```json
{
  "upload_id": "uuid"
}
```

**Response:**
```json
{
  "status": "preserved",
  "ciphertext_hash": "sha256:def456..."
}
```

**Logic:**
1. Validate HMAC signature.
2. Look up `upload_id` in `preservation_files`.
3. Verify file exists in storage at expected path.
4. Update record: `status: 'verifying'`.
5. **Async hash computation:** Trigger a Supabase Edge Function (or background job) to stream-read the blob and compute SHA-256. Vercel serverless functions have a 300-second max timeout (Pro plan) — hashing a 120 GB file at ~500 MB/s takes ~4 minutes, which may exceed this. The Edge Function streams the blob in chunks, computes the hash incrementally, then updates the DB record.
6. When hash computation completes: update record to `status: 'preserved'`, set `ciphertext_hash`, `verified_at`.
7. Log `file_preserved` event to activity log.

**Response:** Returns immediately with `status: 'verifying'`. The client can poll `/api/preservation/status` to see when it transitions to `preserved`.

**Failure:** If hash computation fails or the file is corrupt, status transitions to `failed` with an error in `metadata`.

### 6.3 `GET /api/preservation/status`

**Purpose:** Customer-facing. Returns preservation status for the Trust Dashboard.

**Auth:** Supabase auth (JWT).

**Response:**
```json
{
  "key_status": "split",
  "custodians": [
    { "type": "customer", "display_name": "You", "holds_shard": true },
    { "type": "eternis_primary", "display_name": "Eternis Primary", "holds_shard": true },
    { "type": "eternis_backup", "display_name": "Eternis Backup", "holds_shard": true }
  ],
  "files": [
    {
      "id": "uuid",
      "file_type": "bam",
      "file_size": 128849018880,
      "status": "preserved",
      "ciphertext_hash": "sha256:def456...",
      "plaintext_hash": "sha256:abc123...",
      "created_at": "2026-04-17T12:00:00Z",
      "verified_at": "2026-04-17T12:05:00Z"
    }
  ],
  "activity_log": [
    {
      "event_type": "file_preserved",
      "description": "BAM file preserved and integrity verified",
      "created_at": "2026-04-17T12:05:00Z"
    }
  ],
  "threshold": { "required": 3, "total": 3 }
}
```

### 6.4 `GET /api/preservation/public-key/{sample_id}`

**Purpose:** Sampled calls this to retrieve a customer's X25519 public key for Crypt4GH encryption.

**Auth:** HMAC-SHA256 request signing.

**Response:**
```json
{
  "public_key_b64": "base64-encoded-32-byte-x25519-public-key"
}
```

**Logic:**
1. Validate HMAC signature.
2. Look up `sample_id` → get `profile_id`.
3. Return `profiles.preservation_public_key`.
4. Return 404 if key ceremony hasn't been completed yet.

### 6.5 `POST /api/preservation/verify`

**Purpose:** Re-verify integrity of a specific file (re-hash the stored blob and compare).

**Auth:** Supabase auth (JWT). Customer can trigger re-verification of their own files.

**Logic:**
1. Look up file by ID, verify ownership via RLS.
2. Set file status to `verifying`.
3. **Async:** Trigger Edge Function to stream-read blob from storage, compute SHA-256 incrementally. Same async pattern as `/complete` — large files (60-120 GB) exceed Vercel serverless timeouts.
4. When hash computed: compare against stored `ciphertext_hash`, update `verified_at`, set status back to `preserved`.
5. Log `integrity_verified` event.
6. Return immediately with `status: 'verifying'`. Dashboard polls for completion.

## 7. Trust Dashboard UI

**Research basis:** ProtonDrive security model (wiki/papers/proton-ag-2026-protondrive-security-model.md) — invisible encryption UX. PreVeil Drive (wiki/papers/preveil-2026-drive-encrypted-storage-ux.md) — transparent encryption.

The Trust Dashboard is a new section in the Vault member portal. It shows proof of preservation — not a file browser. Design principle: like a bank vault receipt, not a file manager.

### 7.1 Layout

```
┌─────────────────────────────────────────────────────────┐
│  Genomic Preservation                                    │
│                                                          │
│  ┌──────────────────┐  ┌──────────────────────────────┐ │
│  │ Encryption Status │  │ Key Custodians               │ │
│  │                   │  │                              │ │
│  │ ● Protected       │  │ 3 of 3 required to decrypt   │ │
│  │   AES-256 +       │  │                              │ │
│  │   Crypt4GH        │  │ ✓ You                       │ │
│  │                   │  │ ✓ Eternis Primary            │ │
│  │ Files: 3          │  │ ✓ Eternis Backup             │ │
│  │ Total: 185 GB     │  │                              │ │
│  └──────────────────┘  └──────────────────────────────┘ │
│                                                          │
│  ┌──────────────────────────────────────────────────────┐│
│  │ Integrity Verification                               ││
│  │                                                      ││
│  │  File          Size     Status       Last Verified   ││
│  │  ─────────────────────────────────────────────────── ││
│  │  sample.bam    120 GB   ✓ Verified   2 hours ago    ││
│  │  sample.vcf    2.1 GB   ✓ Verified   2 hours ago    ││
│  │  sample.fastq  63 GB    ✓ Verified   2 hours ago    ││
│  │                                                      ││
│  │  [Verify All Now]                                    ││
│  └──────────────────────────────────────────────────────┘│
│                                                          │
│  ┌──────────────────────────────────────────────────────┐│
│  │ Activity Log                                         ││
│  │                                                      ││
│  │  Apr 17, 2026  BAM file preserved and verified       ││
│  │  Apr 17, 2026  VCF file preserved and verified       ││
│  │  Apr 15, 2026  Encryption keys generated and split   ││
│  │  Apr 15, 2026  Account created                       ││
│  └──────────────────────────────────────────────────────┘│
│                                                          │
│  ┌──────────────────────────────────────────────────────┐│
│  │ Certificate of Preservation                [Print]   ││
│  └──────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

### 7.2 Components

- **EncryptionStatusCard:** Shows encryption standard, file count, total size. Green badge when all files are `preserved`.
- **CustodianCard:** Lists all custodians with their shard-holding status. Shows threshold (e.g., "3 of 3 required"). Does NOT show shard data, key material, or any details about how splitting works — showing this is not a security risk per se, but it adds UX complexity for no customer benefit.
- **IntegrityTable:** Lists each file with type, size, status, and last verification timestamp. "Verify All Now" button triggers `/api/preservation/verify` for each file.
- **ActivityLog:** Chronological list of preservation events from `preservation_activity_log`.
- **CertificateCard:** "Certificate of Preservation" — an HTML print view (not PDF generation for MVP) that summarizes: customer name, file inventory, encryption status, custodian list, integrity hashes, date. Accessible via a [Print] button that opens a print-styled page.

### 7.3 Dashboard Integration

The Trust Dashboard is added as a new card in the existing three-column Vault dashboard (`DashboardClient.tsx`). It sits alongside Sample Status, Epigenetic Profile, Imprint, etc. Clicking the card navigates to the full `/vault/preservation` page.

## 8. Key Ceremony Flow

The key ceremony happens once at customer signup (or on first visit to the preservation section if the account predates this feature).

```
Browser                              Supabase
  │                                      │
  │  Generate X25519 key pair            │
  │  (Web Crypto API)                    │
  │                                      │
  │  Shamir split private key            │
  │  (eternis-crypto shamirSplit)        │
  │  threshold=3, shares=3              │
  │                                      │
  │  Encrypt shard 1 (customer's copy)   │
  │  → offer download / secure store     │
  │                                      │
  │  POST public key + shards 2,3        │
  │ ──────────────────────────────────►  │
  │                                      │
  │  Store:                              │
  │    profiles.preservation_public_key  │
  │    preservation_shards (2 rows)      │
  │    preservation_custodians (3 rows)  │
  │    preservation_activity_log         │
  │                                      │
  │  Erase private key from memory       │
  │  (zero-fill buffer)                  │
```

**Customer's shard:** The customer's shard (shard 1) is encrypted with a key derived from their Supabase auth credentials and offered for download. The customer is responsible for its safekeeping — similar to Keybase's paper key model.

**Eternis shards:** Shards 2 and 3 are encrypted server-side (AES-256-GCM with Eternis-managed KEKs) and stored in `preservation_shards`. These KEKs are managed separately from the customer data encryption and stored in environment variables for MVP (HSM/KMS integration is a future hardening step per OWASP guidance).

## 9. Security Considerations

### 9.1 Trust Model

| Party | Knows | Cannot do alone |
|-------|-------|----------------|
| Customer | Their shard, public key | Decrypt (needs 2 more shards) |
| Eternis | 2 shards, public key | Decrypt (needs customer's shard) |
| Sampled | Public key | Decrypt (has no shards) |
| Attacker (external) | Nothing | Anything |

**Key insight:** Even if Eternis is fully compromised, the attacker gets 2 of 3 shards — still insufficient to reconstruct the private key. The customer's shard is required.

### 9.2 OWASP Alignment

Per OWASP Key Management Cheat Sheet (wiki/papers/owasp-2024-key-management.md):

- **Keys never in plaintext at rest:** Private key exists only transiently in browser memory during key ceremony. Shards are encrypted before storage.
- **Split knowledge / dual control:** 3-of-3 threshold ensures no single party can decrypt.
- **Escrow encryption keys, never signing keys:** We escrow the X25519 encryption key (via Shamir). No signing keys are escrowed.
- **Compromise-recovery plan:** Reshare primitive (3-of-3 → 3-of-5) when beneficiary is added. Activity log provides audit trail.

### 9.3 NIST MPTC Positioning

Per NIST IR 8214C (wiki/papers/nist-2026-threshold-cryptography.md): NIST is actively developing threshold cryptography standards. Eternis's use of Shamir secret sharing for key custody positions it for compliance as these standards finalize.

### 9.4 Browser Memory Erasure Limitation

**Research basis:** W3C Web Cryptography API (wiki/papers/w3c-2024-web-crypto-security-model.md).

The W3C Web Crypto spec explicitly states: "conforming user agents are not required to zeroize key material." During the key ceremony, the X25519 private key exists briefly in browser memory before Shamir splitting and erasure. Mitigations:

- **`Uint8Array.fill(0)`** zeroes the buffer itself but cannot guarantee the JS engine hasn't copied bytes (JIT, GC, stack frames).
- **`extractable=false`** on CryptoKey objects prevents script-level extraction but not OS-level access.
- **Minimize exposure window:** Generate → split → erase in a single synchronous-ish flow. No `await` between generation and erasure except for the Shamir split itself.
- **Accepted risk:** This is an inherent limitation of browser-based cryptography, shared by ProtonDrive, PreVeil, and every browser-based E2E encrypted service. The alternative (server-side key generation) would violate the end-to-end trust model.

### 9.5 Shard Encryption Method

The eternis-crypto library provides `distributeShard()` which encrypts shards with HPKE (X25519+MLKEM768 hybrid) and signs with ML-DSA-65. For MVP, the spec uses simpler AES-256-GCM encryption with Eternis-managed KEKs for Eternis-held shards. Rationale:

- The full `distributeShard()` flow requires HPKE key pairs and ML-DSA-65 signing keys per custodian — infrastructure that doesn't exist at MVP.
- AES-256-GCM with managed KEKs provides confidentiality for shards at rest, which is the primary MVP requirement.
- **Post-MVP:** Migrate to `distributeShard()` when custodian HPKE key pairs are provisioned. This is a storage format migration, not a protocol change.

### 9.6 Threats and Mitigations

| Threat | Mitigation |
|--------|-----------|
| Eternis DB breach | Attacker gets encrypted shards (2 of 3) — cannot reconstruct without customer's shard |
| Sampled breach | Attacker gets encrypted files — cannot decrypt without private key (no shards) |
| Supabase Storage breach | Files are Crypt4GH-encrypted — ciphertext only |
| Customer loses shard | Cannot decrypt without all 3 shards. Future: reshare/recovery flow |
| Man-in-the-middle on upload | TUS over HTTPS. Ciphertext hash verified at `/complete` |
| Corrupt upload | Ciphertext hash mismatch detected at `/complete` → status: `failed` |

## 10. Sampled Integration

### 10.1 What Sampled Needs

1. **API key** for authenticating to `/api/preservation/init` and `/complete`.
2. **Customer's X25519 public key** — retrieved via a new `GET /api/preservation/public-key/{sample_id}` endpoint (authenticated with service API key).
3. **Crypt4GH encryption tooling** — standard GA4GH tooling. Sampled encrypts the file using the customer's public key + Sampled's ephemeral key pair.
4. **TUS upload client** — standard TUS client library. Upload to the presigned URL returned by `/init`.

### 10.2 Sampled Workflow

1. Lab completes sequencing for a sample.
2. Sampled calls `GET /api/preservation/public-key/{sample_id}` → gets customer's X25519 public key.
3. Sampled encrypts the output file with Crypt4GH (customer's public key as recipient).
4. Sampled computes SHA-256 of plaintext before encryption.
5. Sampled calls `POST /api/preservation/init` with metadata + plaintext hash + Crypt4GH header.
6. Sampled uploads encrypted file to presigned TUS URL in 6 MB chunks.
7. Sampled calls `POST /api/preservation/complete`.

### 10.3 Talking Points for Sampled

- Crypt4GH is the GA4GH industry standard — not a custom protocol.
- Standard tooling exists (crypt4gh CLI, libraries in Python/JS/Go).
- Sampled already handles the raw data — adding encryption is one step in their pipeline.
- The public key is provided per-customer; Sampled just uses it.
- TUS upload is standard HTTP — no special infrastructure needed.

## 11. Technology Stack

| Component | Technology | Justification |
|-----------|-----------|--------------|
| Key generation | Web Crypto API (X25519) | Browser-native X25519 key generation (Chrome 113+, Firefox 128+, Safari 17.6+). The eternis-crypto library's `DHKEM_X25519.generateKeyPair()` already uses this — extract the raw 32-byte private key for Shamir splitting. |
| Shamir splitting | eternis-crypto `shamirSplit` | Already built, 221 tests passing (v0.5.0). |
| Encryption standard | GA4GH Crypt4GH | Genomics industry standard. X25519 + ChaCha20-Poly1305. |
| File upload | TUS protocol | Resumable uploads for large files. Supabase implements it. |
| Storage | Supabase Storage (S3-backed) | Already in use for Digital Epigenome. 11 nines durability. |
| Database | Supabase PostgreSQL | Already in use. RLS for access control. |
| Frontend | Next.js + React + Tailwind | Existing Vault stack. |
| Hashing | SHA-256 (Web Crypto API) | Standard, fast, browser-native. |

## 12. Future Phases

These are explicitly NOT in this spec but are on the roadmap:

1. **Beneficiary designation + reshare (3-of-3 → 3-of-5):** Proactive resharing primitive in eternis-crypto.
2. **Option 2 (Eternis encrypts):** Requires streaming Crypt4GH encryption. Would handle cases where Sampled cannot integrate Crypt4GH.
3. **Decryption flow:** Reconstruct private key from 3 shards, decrypt Crypt4GH file, present to authorized party.
4. **Genomic Passport:** Selective disclosure of genomic data for clinical research.
5. **HSM/KMS for Eternis KEKs:** Move from environment variables to hardware security modules.
6. **Certificate of Preservation (PDF):** Upgrade from HTML print view to generated PDF.
7. **Periodic integrity re-verification:** Automated cron job to re-hash all stored blobs.

## 13. Research References

| Topic | Paper | Wiki Path |
|-------|-------|-----------|
| Crypt4GH standard | GA4GH (2021) | wiki/papers/ga4gh-2021-crypt4gh-file-encryption.md |
| Crypt4GH-JS browser | Thelen (2025) | wiki/papers/thelen-2025-crypt4gh-js.md |
| Shamir's Secret Sharing | Shamir (1979) | wiki/papers/shamir-1979-how-to-share-a-secret.md |
| Production Shamir (Vault) | HashiCorp (2024) | wiki/papers/hashicorp-2024-vault-shamir-seal.md |
| Key management best practices | OWASP (2024) | wiki/papers/owasp-2024-key-management.md |
| Threshold cryptography standards | NIST (2026) | wiki/papers/nist-2026-threshold-cryptography.md |
| Resumable uploads | TUS (2024) | wiki/papers/tus-2024-resumable-upload-protocol.md |
| Paper key recovery | Keybase (2024) | wiki/papers/keybase-2024-paper-keys.md |
| Invisible encryption UX | ProtonDrive (2026) | wiki/papers/proton-ag-2026-protondrive-security-model.md |
| Transparent encryption UX | PreVeil (2026) | wiki/papers/preveil-2026-drive-encrypted-storage-ux.md |
| Competitive analysis | GenoBank (2026) | wiki/papers/genobank-2026-platform-analysis.md |
| Patient-owned AI agents | GenoClaw (2026) | wiki/papers/uribe-2026-genoclaw-patient-owned-agents.md |
| API security risks | OWASP (2023) | wiki/papers/owasp-2023-api-security-top-10.md |
| Browser key material limits | W3C (2024) | wiki/papers/w3c-2024-web-crypto-security-model.md |
| HMAC request signing | webhooks.fyi (2024) | wiki/papers/webhooks-fyi-2024-hmac-signature-verification.md |
