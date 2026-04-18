# Vault Genomic Preservation Flow — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate the eternis-crypto library into the Eternis Vault (Next.js/Supabase) to enable end-to-end genomic data preservation with Crypt4GH encryption, Shamir key splitting, HMAC-authenticated API routes, and a Trust Dashboard.

**Architecture:** Six subsystems layered bottom-up: (1) database schema, (2) HMAC auth middleware, (3) Sampled-facing API routes, (4) async hash worker, (5) browser-side key ceremony, (6) Trust Dashboard UI. The eternis-crypto library (v0.5.0, 221 tests) provides `splitKey`, `combineShards`, and `DHKEM_X25519.generateKeyPair()`. Sampled (the lab) encrypts files with GA4GH Crypt4GH using the customer's X25519 public key and uploads via TUS to Supabase Storage.

**Tech Stack:** Next.js 16 (App Router), React 19, Supabase (PostgreSQL + Storage + Edge Functions), Tailwind 4, TypeScript, Vitest, eternis-crypto v0.5.0

**Spec:** `docs/superpowers/specs/2026-04-17-vault-preservation-flow-design.md`

**Note on the vault-mvp codebase:** The previous vault-mvp worktree is no longer on disk. This plan assumes a Next.js App Router project with Supabase already initialized. If the project needs to be recreated, scaffold with `npx create-next-app@latest` + `npx supabase init` before starting Task 1.

**Rate limiting (spec §6.0):** The spec requires 10 req/min general and 1 req/min per sample_id on `/public-key`. This is best handled at the infrastructure level (Vercel Edge Middleware or `@upstash/ratelimit` with Redis). Not included as a task here — implement as a follow-up once the core flow works. The HMAC auth already provides replay protection (5-min window), which mitigates the most critical abuse vector.

---

## File Structure

```
app/
  api/
    preservation/
      _lib/
        hmac-auth.ts          # HMAC-SHA256 request verification middleware
        hmac-auth.test.ts     # Unit tests for HMAC verification
        supabase-admin.ts     # Supabase service-role client (shared)
      init/
        route.ts              # POST /api/preservation/init
      complete/
        route.ts              # POST /api/preservation/complete
      status/
        route.ts              # GET /api/preservation/status
      public-key/
        [sampleId]/
          route.ts            # GET /api/preservation/public-key/[sampleId]
      verify/
        route.ts              # POST /api/preservation/verify
  vault/
    preservation/
      page.tsx                # Trust Dashboard page (server component)
      PreservationDashboard.tsx  # Client component — full dashboard
      EncryptionStatusCard.tsx   # Encryption standard + file count
      CustodianCard.tsx          # Custodian list + threshold
      IntegrityTable.tsx         # File list + verify buttons
      ActivityLog.tsx            # Chronological event list
      CertificateCard.tsx        # Print-ready certificate
    components/
      KeyCeremony.tsx            # Key generation + Shamir split modal
lib/
  preservation.ts              # Shared types + helpers (formatBytes, etc.)
supabase/
  migrations/
    YYYYMMDDHHMMSS_preservation_tables.sql  # Schema migration
  functions/
    compute-hash/
      index.ts                 # Edge Function: stream SHA-256 of stored blob
```

---

### Task 1: Database Schema Migration

**Files:**
- Create: `supabase/migrations/20260417120000_preservation_tables.sql`

- [ ] **Step 1: Write the migration SQL**

```sql
-- Vault Genomic Preservation Flow — schema migration
-- Spec: docs/superpowers/specs/2026-04-17-vault-preservation-flow-design.md §5

-- 1. Add preservation public key to profiles
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS preservation_public_key TEXT;

-- 2. Preservation files (encrypted genomic data records)
CREATE TABLE preservation_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id UUID REFERENCES profiles(id) NOT NULL,
  sample_id UUID REFERENCES samples(id),
  file_type TEXT NOT NULL CHECK (file_type IN ('fastq', 'bam', 'vcf', 'cram', 'other')),
  file_size BIGINT NOT NULL,
  storage_path TEXT NOT NULL,
  crypt4gh_header TEXT NOT NULL,
  plaintext_hash TEXT NOT NULL,
  ciphertext_hash TEXT,
  status TEXT NOT NULL DEFAULT 'uploading'
    CHECK (status IN ('uploading', 'verifying', 'preserved', 'failed')),
  uploaded_by TEXT NOT NULL DEFAULT 'sampled',
  created_at TIMESTAMPTZ DEFAULT now(),
  verified_at TIMESTAMPTZ,
  upload_id TEXT UNIQUE
);

ALTER TABLE preservation_files ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users view own preservation files"
  ON preservation_files FOR SELECT
  USING (profile_id = auth.uid());
