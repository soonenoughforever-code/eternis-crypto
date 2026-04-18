const { generateKey, encryptChunk, decryptChunk, generateMasterKeyPair, wrapKey, unwrapKey, splitKey, combineShards } = await import("./src/index.js");

console.log("=== eternis-crypto v0.3.0 — Full Stack Demo ===\n");

// LAYER 1: AES-256-GCM
console.log("-- Layer 1: AES-256-GCM Chunk Encryption --");
console.log("This encrypts the actual genetic data.\n");

const aesKey = await generateKey();
const genome = new TextEncoder().encode("ATCGATCGATCG... (imagine gigabytes of genomic sequence data)");
console.log("Original data:", new TextDecoder().decode(genome));

const encrypted = await encryptChunk(aesKey, genome, new Uint8Array(0));
console.log("Encrypted:    ", Buffer.from(encrypted.ciphertext).toString("hex").slice(0, 60) + "...");
console.log("Auth tag:     ", Buffer.from(encrypted.tag).toString("hex"));

const decrypted = await decryptChunk(aesKey, encrypted, new Uint8Array(0));
console.log("Decrypted:    ", new TextDecoder().decode(decrypted));
console.log("Layer 1 works -- data encrypted and decrypted\n");

// LAYER 2: HPKE Key Wrapping
console.log("-- Layer 2: HPKE Key Wrapping (Post-Quantum) --");
console.log("This wraps the AES key under a master public key.\n");

const masterKP = await generateMasterKeyPair();
console.log("Master key algorithm:", masterKP.kemId);
console.log("Public key size:     ", masterKP.publicKey.length, "bytes");

const dek = crypto.getRandomValues(new Uint8Array(32));
const wrapped = await wrapKey(dek, masterKP.publicKey);
console.log("Wrapped key enc:     ", Buffer.from(wrapped.enc).toString("hex").slice(0, 60) + "...");

const unwrapped = await unwrapKey(wrapped, masterKP.privateKey);
const dekMatch = Buffer.from(unwrapped).toString("hex") === Buffer.from(dek).toString("hex");
console.log("Unwrapped matches:   ", dekMatch);
console.log("Layer 2 works -- AES key wrapped with post-quantum KEM\n");

// LAYER 3: Shamir Key Splitting
console.log("-- Layer 3: Shamir Key Splitting --");
console.log("This splits the master key into 5 shards (need 3 to recover).\n");

const masterSecret = crypto.getRandomValues(new Uint8Array(32));
console.log("Master secret:", Buffer.from(masterSecret).toString("hex").slice(0, 40) + "...");

const splitResult = await splitKey(masterSecret, { threshold: 3, shares: 5 });
console.log("Split into " + splitResult.shards.length + " shards (threshold: " + splitResult.threshold + "):\n");

for (const shard of splitResult.shards) {
  console.log("  Shard " + shard.index + ":");
  console.log("    Value: " + Buffer.from(shard.value).toString("hex").slice(0, 40) + "...");
  console.log("    MAC:   " + Buffer.from(shard.mac).toString("hex").slice(0, 40) + "...");
}

// Reconstruct with only 3 of 5
console.log("\n-- Reconstruction with shards 1, 3, 5 --");
const subset = [splitResult.shards[0], splitResult.shards[2], splitResult.shards[4]];
const recovered = await combineShards(subset);
const secretMatch = Buffer.from(recovered).toString("hex") === Buffer.from(masterSecret).toString("hex");
console.log("Recovered secret:", Buffer.from(recovered).toString("hex").slice(0, 40) + "...");
console.log("Matches original:", secretMatch);
console.log("Layer 3 works -- master key split and recovered from 3 of 5 shards\n");

// TAMPER DETECTION
console.log("-- Tamper Detection Demo --");
console.log("What happens if someone modifies a shard?\n");

const tamperedShards = splitResult.shards.map(function(s: any) { return {...s}; });
const badValue = new Uint8Array(tamperedShards[1].value);
badValue[0] = badValue[0] ^ 0x01;
tamperedShards[1] = { ...tamperedShards[1], value: badValue };

try {
  await combineShards([tamperedShards[0], tamperedShards[1], tamperedShards[2]]);
  console.log("ERROR: should have thrown!");
} catch (e: any) {
  console.log("Caught: " + e.constructor.name);
  console.log("Message: " + e.message);
  console.log("Tampered shard detected -- reconstruction rejected\n");
}

// THE FULL PICTURE
console.log("============================================");
console.log("THE FULL STACK:");
console.log("============================================");
console.log("");
console.log("  Genetic data (gigabytes)");
console.log("      | encrypted by");
console.log("  AES-256-GCM (v0.1) -- hardware-accelerated");
console.log("      | the AES key is protected by");
console.log("  HPKE Key Wrapping (v0.2) -- post-quantum safe");
console.log("      | the master key is split into");
console.log("  Shamir Shards (v0.3) -- 3-of-5, info-theoretically secure");
console.log("      | shards distributed to");
console.log("  Trusted custodians (future: Vault platform)");
console.log("");
console.log("No single point of failure. Quantum-resistant.");
console.log("Designed for 50 years.");
