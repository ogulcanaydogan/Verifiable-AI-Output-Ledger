"""Tests for client-side cryptographic verification (Ed25519 DSSE + Merkle proofs)."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaol.verify import (
    VerifyResult,
    verify_dsse_ed25519,
    verify_inclusion_proof,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PAYLOAD_TYPE = "application/vnd.vaol.decision-record.v1+json"


def _pae(payload_type: str, payload: bytes) -> bytes:
    return f"DSSEv1 {len(payload_type)} {payload_type} {len(payload)} ".encode() + payload


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _make_envelope(payload: bytes, private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Create a valid DSSE envelope signed with the given key."""
    pae = _pae(PAYLOAD_TYPE, payload)
    sig = private_key.sign(pae)
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": _b64(payload),
        "signatures": [{"keyid": "test-key", "sig": _b64(sig)}],
    }


def _merkle_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _merkle_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _prefixed(b: bytes) -> str:
    return "sha256:" + b.hex()


# ---------------------------------------------------------------------------
# DSSE Ed25519 verification tests
# ---------------------------------------------------------------------------

class TestVerifyDSSEEd25519:
    def test_valid_signature(self) -> None:
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes_raw()
        payload = json.dumps({"request_id": "test-1"}).encode()
        envelope = _make_envelope(payload, priv)

        result = verify_dsse_ed25519(envelope, pub_bytes)
        assert result.valid is True
        assert len(result.checks) == 1
        assert result.checks[0]["passed"] is True

    def test_invalid_signature(self) -> None:
        priv = Ed25519PrivateKey.generate()
        other_priv = Ed25519PrivateKey.generate()
        other_pub = other_priv.public_key().public_bytes_raw()
        payload = b'{"request_id": "wrong-key"}'
        envelope = _make_envelope(payload, priv)

        result = verify_dsse_ed25519(envelope, other_pub)
        assert result.valid is False

    def test_no_signatures(self) -> None:
        envelope: dict[str, Any] = {
            "payloadType": PAYLOAD_TYPE,
            "payload": _b64(b"data"),
            "signatures": [],
        }
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes_raw()
        result = verify_dsse_ed25519(envelope, pub_bytes)
        assert result.valid is False
        assert result.checks[0]["name"] == "signature_present"

    def test_corrupted_payload(self) -> None:
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes_raw()
        payload = b'{"request_id": "test-2"}'
        envelope = _make_envelope(payload, priv)
        # Tamper with payload
        envelope["payload"] = _b64(b"tampered")

        result = verify_dsse_ed25519(envelope, pub_bytes)
        assert result.valid is False

    def test_summary_all_passed(self) -> None:
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes_raw()
        envelope = _make_envelope(b'{"ok": true}', priv)
        result = verify_dsse_ed25519(envelope, pub_bytes)
        assert result.summary == "all checks passed"

    def test_summary_failed(self) -> None:
        result = VerifyResult(valid=False, checks=[{"name": "sig_0", "passed": False}])
        assert "sig_0" in result.summary


# ---------------------------------------------------------------------------
# Merkle inclusion proof tests
# ---------------------------------------------------------------------------

class TestVerifyInclusionProof:
    def test_single_leaf_tree(self) -> None:
        leaf = b"leaf-0"
        leaf_hash = _merkle_leaf(leaf)
        root = _prefixed(leaf_hash)

        result = verify_inclusion_proof(
            leaf_data=leaf,
            leaf_index=0,
            tree_size=1,
            proof_hashes=[],
            expected_root=root,
        )
        assert result.valid is True

    def test_two_leaf_tree(self) -> None:
        leaf0 = b"leaf-0"
        leaf1 = b"leaf-1"
        h0 = _merkle_leaf(leaf0)
        h1 = _merkle_leaf(leaf1)
        root = _merkle_node(h0, h1)
        root_str = _prefixed(root)

        # Verify leaf 0 with sibling h1
        result = verify_inclusion_proof(
            leaf_data=leaf0,
            leaf_index=0,
            tree_size=2,
            proof_hashes=[_prefixed(h1)],
            expected_root=root_str,
        )
        assert result.valid is True

        # Verify leaf 1 with sibling h0
        result = verify_inclusion_proof(
            leaf_data=leaf1,
            leaf_index=1,
            tree_size=2,
            proof_hashes=[_prefixed(h0)],
            expected_root=root_str,
        )
        assert result.valid is True

    def test_three_leaf_tree(self) -> None:
        """Tree structure for 3 leaves:
              root
             /    \\
           n01     h2
          /   \\
         h0    h1
        """
        leaf0, leaf1, leaf2 = b"a", b"b", b"c"
        h0 = _merkle_leaf(leaf0)
        h1 = _merkle_leaf(leaf1)
        h2 = _merkle_leaf(leaf2)
        n01 = _merkle_node(h0, h1)
        root = _merkle_node(n01, h2)
        root_str = _prefixed(root)

        # Verify leaf 0: path = [h1, h2] (sibling then right subtree)
        result = verify_inclusion_proof(
            leaf_data=leaf0,
            leaf_index=0,
            tree_size=3,
            proof_hashes=[_prefixed(h1), _prefixed(h2)],
            expected_root=root_str,
        )
        assert result.valid is True

        # Verify leaf 2: path = [n01]
        result = verify_inclusion_proof(
            leaf_data=leaf2,
            leaf_index=2,
            tree_size=3,
            proof_hashes=[_prefixed(n01)],
            expected_root=root_str,
        )
        assert result.valid is True

    def test_wrong_root(self) -> None:
        leaf = b"leaf-0"
        leaf_hash = _merkle_leaf(leaf)
        result = verify_inclusion_proof(
            leaf_data=leaf,
            leaf_index=0,
            tree_size=1,
            proof_hashes=[],
            expected_root="sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        assert result.valid is False
        assert "inclusion_proof" in result.checks[0]["name"]

    def test_invalid_tree_size(self) -> None:
        result = verify_inclusion_proof(b"x", 0, 0, [], "sha256:abc")
        assert result.valid is False
        assert "tree_size" in result.checks[0]["name"]

    def test_invalid_leaf_index(self) -> None:
        result = verify_inclusion_proof(b"x", 5, 3, [], "sha256:abc")
        assert result.valid is False
        assert "leaf_index" in result.checks[0]["name"]

    def test_negative_leaf_index(self) -> None:
        result = verify_inclusion_proof(b"x", -1, 3, [], "sha256:abc")
        assert result.valid is False
