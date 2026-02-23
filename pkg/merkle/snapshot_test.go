package merkle

import (
	"fmt"
	"strings"
	"testing"
)

func TestSnapshotPayloadEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	tree := New()
	for i := 0; i < 10; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}

	payload, err := SnapshotPayloadFromTree(tree)
	if err != nil {
		t.Fatalf("SnapshotPayloadFromTree: %v", err)
	}

	restoredTree, err := TreeFromSnapshotPayload(payload)
	if err != nil {
		t.Fatalf("TreeFromSnapshotPayload: %v", err)
	}
	if restoredTree.Size() != tree.Size() {
		t.Fatalf("restored size = %d, want %d", restoredTree.Size(), tree.Size())
	}
	if restoredTree.Root() != tree.Root() {
		t.Fatalf("restored root = %s, want %s", restoredTree.Root(), tree.Root())
	}
}

func TestSnapshotPayloadDecodeRejectsCorruption(t *testing.T) {
	t.Parallel()

	payload, err := EncodeSnapshotPayload([][]byte{})
	if err != nil {
		t.Fatalf("EncodeSnapshotPayload: %v", err)
	}
	payload[0] = 'X'

	_, err = DecodeSnapshotPayload(payload)
	if err == nil {
		t.Fatal("expected decode error for corrupted magic")
	}
	if !strings.Contains(err.Error(), "invalid snapshot magic") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSnapshotPayloadDecodeRejectsLengthMismatch(t *testing.T) {
	t.Parallel()

	tree := New()
	tree.Append([]byte("only-leaf"))
	payload, err := SnapshotPayloadFromTree(tree)
	if err != nil {
		t.Fatalf("SnapshotPayloadFromTree: %v", err)
	}

	// Truncate to force deterministic size mismatch.
	payload = payload[:len(payload)-1]
	_, err = DecodeSnapshotPayload(payload)
	if err == nil {
		t.Fatal("expected decode error for payload truncation")
	}
	if !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}
