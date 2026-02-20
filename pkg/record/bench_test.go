package record

import (
	"encoding/json"
	"testing"
)

func BenchmarkCanonicalize(b *testing.B) {
	rec := makeTestRecord()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Canonicalize(rec); err != nil {
			b.Fatalf("Canonicalize: %v", err)
		}
	}
}

func BenchmarkComputeRecordHash(b *testing.B) {
	rec := makeTestRecord()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ComputeRecordHash(rec); err != nil {
			b.Fatalf("ComputeRecordHash: %v", err)
		}
	}
}

func BenchmarkJSONMarshalRecord(b *testing.B) {
	rec := makeTestRecord()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(rec); err != nil {
			b.Fatalf("json.Marshal: %v", err)
		}
	}
}
