package merkle

import (
	"fmt"
	"strings"
	"testing"

	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
)

func TestVerifyInclusionSingleLeaf(t *testing.T) {
	tree := New()
	leaf := []byte("only-leaf")
	tree.Append(leaf)

	proof, err := tree.InclusionProof(0, tree.Size())
	if err != nil {
		t.Fatalf("InclusionProof error: %v", err)
	}

	if err := VerifyInclusion(leaf, proof); err != nil {
		t.Errorf("VerifyInclusion should pass for single leaf: %v", err)
	}
}

func TestVerifyInclusionMultiLeaf(t *testing.T) {
	tree := New()
	leaves := make([][]byte, 8)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
		tree.Append(leaves[i])
	}

	treeSize := tree.Size()
	for i, leaf := range leaves {
		proof, err := tree.InclusionProof(int64(i), treeSize)
		if err != nil {
			t.Fatalf("leaf %d: InclusionProof error: %v", i, err)
		}
		if err := VerifyInclusion(leaf, proof); err != nil {
			t.Errorf("leaf %d: VerifyInclusion failed: %v", i, err)
		}
	}
}

func TestVerifyInclusionWrongRootHash(t *testing.T) {
	tree := New()
	leaf := []byte("test-leaf")
	tree.Append(leaf)
	tree.Append([]byte("other-leaf"))

	proof, err := tree.InclusionProof(0, tree.Size())
	if err != nil {
		t.Fatalf("InclusionProof error: %v", err)
	}

	proof.RootHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	err = VerifyInclusion(leaf, proof)
	if err == nil {
		t.Fatal("VerifyInclusion should fail with wrong root hash")
	}
	if !strings.Contains(err.Error(), "inclusion proof invalid") {
		t.Errorf("error should contain 'inclusion proof invalid', got: %v", err)
	}
}

func TestVerifyInclusionWrongProofType(t *testing.T) {
	proof := &Proof{
		ProofType: ProofTypeConsistency,
		LeafIndex: 0,
		TreeSize:  1,
		RootHash:  "sha256:abc",
	}

	err := VerifyInclusion([]byte("data"), proof)
	if err == nil {
		t.Fatal("VerifyInclusion should fail with wrong proof type")
	}
	if !strings.Contains(err.Error(), "expected inclusion proof") {
		t.Errorf("error should contain 'expected inclusion proof', got: %v", err)
	}
}

func TestRootFromInclusionProofTreeSizeZero(t *testing.T) {
	hash := vaolcrypto.MerkleLeafHash([]byte("data"))
	_, err := rootFromInclusionProof(hash, 0, 0, nil)
	if err == nil {
		t.Fatal("should fail with treeSize=0")
	}
	if !strings.Contains(err.Error(), "tree size must be positive") {
		t.Errorf("error should contain 'tree size must be positive', got: %v", err)
	}
}

func TestRootFromInclusionProofLeafIndexOutOfRange(t *testing.T) {
	hash := vaolcrypto.MerkleLeafHash([]byte("data"))

	// leafIndex >= treeSize
	_, err := rootFromInclusionProof(hash, 5, 5, nil)
	if err == nil {
		t.Fatal("should fail with leafIndex >= treeSize")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error should contain 'out of range', got: %v", err)
	}

	// negative leafIndex
	_, err = rootFromInclusionProof(hash, -1, 5, nil)
	if err == nil {
		t.Fatal("should fail with negative leafIndex")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error should contain 'out of range', got: %v", err)
	}
}

func TestRootFromInclusionProofInvalidHashEncoding(t *testing.T) {
	hash := vaolcrypto.MerkleLeafHash([]byte("data"))
	_, err := rootFromInclusionProof(hash, 0, 2, []string{"not-a-valid-hash"})
	if err == nil {
		t.Fatal("should fail with invalid hash encoding")
	}
	if !strings.Contains(err.Error(), "decoding proof hash") {
		t.Errorf("error should contain 'decoding proof hash', got: %v", err)
	}
}

func TestRecomputeRootEmptyPath(t *testing.T) {
	hash := vaolcrypto.MerkleLeafHash([]byte("data"))
	_, err := recomputeRoot(hash, 0, 2, nil)
	if err == nil {
		t.Fatal("should fail with empty path and size > 1")
	}
	if !strings.Contains(err.Error(), "insufficient proof hashes") {
		t.Errorf("error should contain 'insufficient proof hashes', got: %v", err)
	}
}

func TestRecomputeRootExcessPath(t *testing.T) {
	hash := vaolcrypto.MerkleLeafHash([]byte("data"))
	extra := vaolcrypto.MerkleLeafHash([]byte("extra"))
	_, err := recomputeRoot(hash, 0, 1, [][]byte{extra})
	if err == nil {
		t.Fatal("should fail with excess path for single-leaf tree")
	}
	if !strings.Contains(err.Error(), "excess proof hashes") {
		t.Errorf("error should contain 'excess proof hashes', got: %v", err)
	}
}
