package merkle

import (
	"encoding/binary"
	"fmt"
)

const (
	snapshotMagic       = "VAOLMS01"
	snapshotHeaderSize  = 16
	snapshotLeafHashLen = 32
)

// EncodeSnapshotPayload packs RFC 6962 leaf hashes into a deterministic binary
// snapshot payload:
//
//	magic(8) | leaf_count_u64_be(8) | leaf_0(32) | ... | leaf_n(32)
func EncodeSnapshotPayload(leafHashes [][]byte) ([]byte, error) {
	if len(leafHashes) == 0 {
		return append([]byte(snapshotMagic), make([]byte, 8)...), nil
	}

	payload := make([]byte, snapshotHeaderSize+len(leafHashes)*snapshotLeafHashLen)
	copy(payload, []byte(snapshotMagic))
	binary.BigEndian.PutUint64(payload[8:16], uint64(len(leafHashes)))

	offset := snapshotHeaderSize
	for i, leafHash := range leafHashes {
		if len(leafHash) != snapshotLeafHashLen {
			return nil, fmt.Errorf("leaf hash at index %d has length %d, expected %d", i, len(leafHash), snapshotLeafHashLen)
		}
		copy(payload[offset:offset+snapshotLeafHashLen], leafHash)
		offset += snapshotLeafHashLen
	}

	return payload, nil
}

// DecodeSnapshotPayload decodes packed leaf hashes from EncodeSnapshotPayload.
func DecodeSnapshotPayload(payload []byte) ([][]byte, error) {
	if len(payload) < snapshotHeaderSize {
		return nil, fmt.Errorf("snapshot payload too small: got %d bytes", len(payload))
	}
	if string(payload[:8]) != snapshotMagic {
		return nil, fmt.Errorf("invalid snapshot magic")
	}

	leafCount := binary.BigEndian.Uint64(payload[8:16])
	maxLeafCount := uint64((len(payload) - snapshotHeaderSize) / snapshotLeafHashLen)
	if leafCount > maxLeafCount {
		return nil, fmt.Errorf("snapshot payload size mismatch: leaf_count=%d exceeds maximum=%d", leafCount, maxLeafCount)
	}
	expected := uint64(snapshotHeaderSize) + leafCount*uint64(snapshotLeafHashLen)
	if expected != uint64(len(payload)) {
		return nil, fmt.Errorf("snapshot payload size mismatch: got=%d expected=%d", len(payload), expected)
	}

	leafHashes := make([][]byte, 0)
	offset := snapshotHeaderSize
	for i := uint64(0); i < leafCount; i++ {
		hash := make([]byte, snapshotLeafHashLen)
		copy(hash, payload[offset:offset+snapshotLeafHashLen])
		leafHashes = append(leafHashes, hash)
		offset += snapshotLeafHashLen
	}
	return leafHashes, nil
}

// SnapshotPayloadFromTree serializes current in-memory leaf hashes.
func SnapshotPayloadFromTree(tree *Tree) ([]byte, error) {
	if tree == nil {
		return nil, fmt.Errorf("tree is nil")
	}

	tree.mu.RLock()
	leafHashes := make([][]byte, len(tree.leaves))
	for i, leaf := range tree.leaves {
		cp := make([]byte, len(leaf))
		copy(cp, leaf)
		leafHashes[i] = cp
	}
	tree.mu.RUnlock()

	return EncodeSnapshotPayload(leafHashes)
}

// TreeFromSnapshotPayload reconstructs an in-memory Merkle tree from packed
// leaf hashes.
func TreeFromSnapshotPayload(payload []byte) (*Tree, error) {
	leafHashes, err := DecodeSnapshotPayload(payload)
	if err != nil {
		return nil, err
	}
	return NewFromLeaves(leafHashes), nil
}
