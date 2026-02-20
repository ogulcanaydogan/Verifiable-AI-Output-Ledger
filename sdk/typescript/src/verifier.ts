/**
 * Client-side cryptographic verification for VAOL decision records.
 *
 * Provides Ed25519 DSSE signature verification and RFC 6962 Merkle
 * inclusion proof validation — enabling auditors to verify records
 * without trusting the server.
 */

import { createHash, verify as cryptoVerify } from "node:crypto";
import type { DSSEEnvelope } from "./types.js";

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

export interface VerifyCheck {
  name: string;
  passed: boolean;
  error?: string;
}

export interface VerifyResult {
  valid: boolean;
  checks: VerifyCheck[];
}

// ---------------------------------------------------------------------------
// DSSE helpers
// ---------------------------------------------------------------------------

function pae(payloadType: string, payload: Buffer): Buffer {
  const prefix = Buffer.from(
    `DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `,
    "utf-8",
  );
  return Buffer.concat([prefix, payload]);
}

function b64Decode(s: string): Buffer {
  // Handle both standard and URL-safe base64
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

// ---------------------------------------------------------------------------
// Ed25519 DSSE verification
// ---------------------------------------------------------------------------

/**
 * Verify Ed25519 signatures on a DSSE envelope.
 *
 * @param envelope - DSSE envelope object
 * @param publicKey - Raw 32-byte Ed25519 public key
 * @returns Verification result with per-signature check details
 */
export function verifyDSSEEd25519(
  envelope: DSSEEnvelope,
  publicKey: Buffer,
): VerifyResult {
  const checks: VerifyCheck[] = [];

  if (!envelope.signatures?.length) {
    checks.push({ name: "signature_present", passed: false, error: "no signatures" });
    return { valid: false, checks };
  }

  let payload: Buffer;
  try {
    payload = b64Decode(envelope.payload);
  } catch (err) {
    checks.push({
      name: "payload_decode",
      passed: false,
      error: String(err),
    });
    return { valid: false, checks };
  }

  const message = pae(envelope.payloadType, payload);

  let verifiedCount = 0;
  for (let i = 0; i < envelope.signatures.length; i++) {
    const sig = envelope.signatures[i];
    const name = `signature_${i}`;
    try {
      const sigBytes = b64Decode(sig.sig);
      const keyObject = {
        key: Buffer.concat([
          // Ed25519 public key DER prefix
          Buffer.from("302a300506032b6570032100", "hex"),
          publicKey,
        ]),
        format: "der" as const,
        type: "spki" as const,
      };
      const ok = cryptoVerify(null, message, keyObject, sigBytes);
      if (ok) {
        checks.push({ name, passed: true });
        verifiedCount++;
      } else {
        checks.push({ name, passed: false, error: "signature invalid" });
      }
    } catch (err) {
      checks.push({ name, passed: false, error: String(err) });
    }
  }

  return { valid: verifiedCount > 0, checks };
}

// ---------------------------------------------------------------------------
// Merkle proof verification (RFC 6962)
// ---------------------------------------------------------------------------

function merkleLeafHash(data: Buffer): Buffer {
  const h = createHash("sha256");
  h.update(Buffer.from([0x00]));
  h.update(data);
  return h.digest();
}

function merkleNodeHash(left: Buffer, right: Buffer): Buffer {
  const h = createHash("sha256");
  h.update(Buffer.from([0x01]));
  h.update(left);
  h.update(right);
  return h.digest();
}

function largestPowerOf2LessThan(n: number): number {
  if (n <= 1) return 0;
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function hashFromPrefixed(prefixed: string): Buffer {
  if (!prefixed.startsWith("sha256:")) {
    throw new Error(`expected sha256: prefix, got "${prefixed}"`);
  }
  return Buffer.from(prefixed.slice(7), "hex");
}

function bytesToPrefixed(b: Buffer): string {
  return `sha256:${b.toString("hex")}`;
}

function recomputeRoot(
  hash: Buffer,
  index: number,
  size: number,
  path: Buffer[],
): Buffer {
  if (size === 1) {
    if (path.length !== 0) throw new Error("excess proof hashes for single-leaf tree");
    return hash;
  }
  if (path.length === 0) throw new Error("insufficient proof hashes");

  const k = largestPowerOf2LessThan(size);
  const sibling = path[path.length - 1];
  const remaining = path.slice(0, -1);

  if (index < k) {
    const sub = recomputeRoot(hash, index, k, remaining);
    return merkleNodeHash(sub, sibling);
  }

  const sub = recomputeRoot(hash, index - k, size - k, remaining);
  return merkleNodeHash(sibling, sub);
}

/**
 * Verify a Merkle inclusion proof per RFC 6962.
 *
 * @param leafData - Raw leaf payload (e.g. canonical JSON of the record)
 * @param leafIndex - Zero-based index of the leaf in the tree
 * @param treeSize - Total number of leaves when the proof was generated
 * @param proofHashes - `sha256:<hex>` sibling hashes from leaf to root
 * @param expectedRoot - `sha256:<hex>` expected Merkle root
 */
export function verifyInclusionProof(
  leafData: Buffer,
  leafIndex: number,
  treeSize: number,
  proofHashes: string[],
  expectedRoot: string,
): VerifyResult {
  const checks: VerifyCheck[] = [];

  if (treeSize <= 0) {
    checks.push({ name: "tree_size", passed: false, error: "tree size must be positive" });
    return { valid: false, checks };
  }

  if (leafIndex < 0 || leafIndex >= treeSize) {
    checks.push({
      name: "leaf_index",
      passed: false,
      error: `leaf index ${leafIndex} out of range [0, ${treeSize})`,
    });
    return { valid: false, checks };
  }

  let pathBuffers: Buffer[];
  try {
    pathBuffers = proofHashes.map(hashFromPrefixed);
  } catch (err) {
    checks.push({ name: "proof_decode", passed: false, error: String(err) });
    return { valid: false, checks };
  }

  const leafHash = merkleLeafHash(leafData);

  let computedRoot: Buffer;
  try {
    computedRoot = recomputeRoot(leafHash, leafIndex, treeSize, pathBuffers);
  } catch (err) {
    checks.push({ name: "proof_recompute", passed: false, error: String(err) });
    return { valid: false, checks };
  }

  const computedStr = bytesToPrefixed(computedRoot);
  if (computedStr === expectedRoot) {
    checks.push({ name: "inclusion_proof", passed: true });
    return { valid: true, checks };
  }

  checks.push({
    name: "inclusion_proof",
    passed: false,
    error: `computed root ${computedStr} != expected ${expectedRoot}`,
  });
  return { valid: false, checks };
}
