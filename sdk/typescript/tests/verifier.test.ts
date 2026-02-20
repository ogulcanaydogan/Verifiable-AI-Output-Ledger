import { describe, it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { verifyDSSEEd25519, verifyInclusionProof } from "../src/verifier.js";
import type { DSSEEnvelope } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PAYLOAD_TYPE = "application/vnd.vaol.decision-record.v1+json";

function b64(data: Buffer): string {
  return data.toString("base64");
}

function pae(payloadType: string, payload: Buffer): Buffer {
  const prefix = Buffer.from(
    `DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `,
    "utf-8",
  );
  return Buffer.concat([prefix, payload]);
}

function makeEnvelope(payload: Buffer, privateKey: Buffer, publicKey: Buffer): DSSEEnvelope {
  const message = pae(PAYLOAD_TYPE, payload);
  const keyObj = {
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), privateKey]),
    format: "der" as const,
    type: "pkcs8" as const,
  };
  const sig = sign(null, message, keyObj);
  return {
    payloadType: PAYLOAD_TYPE,
    payload: b64(payload),
    signatures: [{ keyid: "test-key", sig: b64(sig) }],
  };
}

function generateEd25519Keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubRaw = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  const privRaw = privateKey.export({ format: "der", type: "pkcs8" }).subarray(16);
  return { pubRaw, privRaw };
}

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

function prefixed(b: Buffer): string {
  return `sha256:${b.toString("hex")}`;
}

// ---------------------------------------------------------------------------
// DSSE Ed25519 tests
// ---------------------------------------------------------------------------

describe("verifyDSSEEd25519", () => {
  it("verifies a valid signature", () => {
    const { pubRaw, privRaw } = generateEd25519Keys();
    const payload = Buffer.from(JSON.stringify({ request_id: "test-1" }));
    const envelope = makeEnvelope(payload, privRaw, pubRaw);

    const result = verifyDSSEEd25519(envelope, pubRaw);
    expect(result.valid).toBe(true);
    expect(result.checks).toHaveLength(1);
    expect(result.checks[0].passed).toBe(true);
  });

  it("rejects signature with wrong key", () => {
    const keys1 = generateEd25519Keys();
    const keys2 = generateEd25519Keys();
    const payload = Buffer.from('{"id":"wrong-key"}');
    const envelope = makeEnvelope(payload, keys1.privRaw, keys1.pubRaw);

    const result = verifyDSSEEd25519(envelope, keys2.pubRaw);
    expect(result.valid).toBe(false);
  });

  it("rejects envelope with no signatures", () => {
    const { pubRaw } = generateEd25519Keys();
    const envelope: DSSEEnvelope = {
      payloadType: PAYLOAD_TYPE,
      payload: b64(Buffer.from("data")),
      signatures: [],
    };

    const result = verifyDSSEEd25519(envelope, pubRaw);
    expect(result.valid).toBe(false);
    expect(result.checks[0].name).toBe("signature_present");
  });

  it("rejects tampered payload", () => {
    const { pubRaw, privRaw } = generateEd25519Keys();
    const payload = Buffer.from('{"request_id":"test-2"}');
    const envelope = makeEnvelope(payload, privRaw, pubRaw);
    envelope.payload = b64(Buffer.from("tampered"));

    const result = verifyDSSEEd25519(envelope, pubRaw);
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Merkle inclusion proof tests
// ---------------------------------------------------------------------------

describe("verifyInclusionProof", () => {
  it("verifies a single-leaf tree", () => {
    const leaf = Buffer.from("leaf-0");
    const leafHash = merkleLeafHash(leaf);
    const root = prefixed(leafHash);

    const result = verifyInclusionProof(leaf, 0, 1, [], root);
    expect(result.valid).toBe(true);
  });

  it("verifies leaf 0 in a two-leaf tree", () => {
    const leaf0 = Buffer.from("leaf-0");
    const leaf1 = Buffer.from("leaf-1");
    const h0 = merkleLeafHash(leaf0);
    const h1 = merkleLeafHash(leaf1);
    const root = merkleNodeHash(h0, h1);

    const result = verifyInclusionProof(leaf0, 0, 2, [prefixed(h1)], prefixed(root));
    expect(result.valid).toBe(true);
  });

  it("verifies leaf 1 in a two-leaf tree", () => {
    const leaf0 = Buffer.from("leaf-0");
    const leaf1 = Buffer.from("leaf-1");
    const h0 = merkleLeafHash(leaf0);
    const h1 = merkleLeafHash(leaf1);
    const root = merkleNodeHash(h0, h1);

    const result = verifyInclusionProof(leaf1, 1, 2, [prefixed(h0)], prefixed(root));
    expect(result.valid).toBe(true);
  });

  it("verifies leaf in a three-leaf tree", () => {
    const a = Buffer.from("a");
    const b = Buffer.from("b");
    const c = Buffer.from("c");
    const h0 = merkleLeafHash(a);
    const h1 = merkleLeafHash(b);
    const h2 = merkleLeafHash(c);
    const n01 = merkleNodeHash(h0, h1);
    const root = merkleNodeHash(n01, h2);

    // Verify leaf 0: path = [h1, h2]
    const r0 = verifyInclusionProof(a, 0, 3, [prefixed(h1), prefixed(h2)], prefixed(root));
    expect(r0.valid).toBe(true);

    // Verify leaf 2: path = [n01]
    const r2 = verifyInclusionProof(c, 2, 3, [prefixed(n01)], prefixed(root));
    expect(r2.valid).toBe(true);
  });

  it("rejects wrong root", () => {
    const leaf = Buffer.from("leaf-0");
    const result = verifyInclusionProof(
      leaf,
      0,
      1,
      [],
      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    expect(result.valid).toBe(false);
  });

  it("rejects invalid tree size", () => {
    const result = verifyInclusionProof(Buffer.from("x"), 0, 0, [], "sha256:abc");
    expect(result.valid).toBe(false);
    expect(result.checks[0].name).toBe("tree_size");
  });

  it("rejects out-of-range leaf index", () => {
    const result = verifyInclusionProof(Buffer.from("x"), 5, 3, [], "sha256:abc");
    expect(result.valid).toBe(false);
    expect(result.checks[0].name).toBe("leaf_index");
  });

  it("rejects negative leaf index", () => {
    const result = verifyInclusionProof(Buffer.from("x"), -1, 3, [], "sha256:abc");
    expect(result.valid).toBe(false);
  });
});
