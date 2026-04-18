# Preservation Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `preserve()` and `recover()` functions that chain AES-256-GCM, Shamir splitting, and shard encryption (HPKE + ML-DSA-65) into a single pipeline.

**Architecture:** Two public functions (`preserve`, `recover`) in `src/pipeline.ts` that compose existing primitives. DEK is generated internally, split directly via Shamir, and each shard is signed + encrypted per custodian. No new cryptographic logic — just wiring.

**Tech Stack:** TypeScript, Vitest, Web Crypto API, existing eternis-crypto primitives (v0.1–v0.4)

---

### Task 1: Add PreservationPackage type

**Files:**
- Modify: `src/types.ts:87` (append after EncryptedShard interface)

- [ ] **Step 1: Add the PreservationPackage interface**

Add this interface at the end of `src/types.ts`:

```typescript
/** The complete output of a preserve() call — everything needed to recover the data. */
export interface PreservationPackage {
  /** AES-256-GCM encrypted data. */
  readonly encryptedData: {
    readonly ciphertext: Uint8Array;
    readonly iv: Uint8Array;
    readonly tag: Uint8Array;
  };
  /** One encrypted shard per custodian, each signed (ML-DSA-65) and encrypted (HPKE). */
  readonly encryptedShards: EncryptedShard[];
  /** Pipeline metadata needed for recovery. */
  readonly metadata: {
    readonly version: string;
    readonly threshold: number;
    readonly totalShards: number;
    readonly kemId: string;
    readonly sigAlgorithmId: string;
  };
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors (type is defined but not yet used)

- [ ] **Step 3: Commit**

```bash
git add src/types.ts
git commit -m "feat: add PreservationPackage type for v0.5 pipeline"
```

---

### Task 2: Implement preserve() with round-trip test

**Files:**