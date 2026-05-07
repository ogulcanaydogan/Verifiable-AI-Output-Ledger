package valerr_test

import (
	"testing"

	"github.com/ogulcanaydogan/vaol/pkg/valerr"
)

func TestCodeValues(t *testing.T) {
	tests := []struct {
		code valerr.Code
		want string
	}{
		{valerr.CodeRecordNotFound, "VAOL_RECORD_NOT_FOUND"},
		{valerr.CodePolicyDenied, "VAOL_POLICY_DENIED"},
		{valerr.CodeDuplicateRequestID, "VAOL_DUPLICATE_REQUEST_ID"},
		{valerr.CodeInternalError, "VAOL_INTERNAL_ERROR"},
		{valerr.CodeInvalidRequestBody, "VAOL_INVALID_REQUEST_BODY"},
		{valerr.CodeProofNotFound, "VAOL_PROOF_NOT_FOUND"},
	}
	for _, tc := range tests {
		if string(tc.code) != tc.want {
			t.Errorf("code %q: got %q, want %q", tc.code, string(tc.code), tc.want)
		}
	}
}

func TestCodeIsString(t *testing.T) {
	// Ensure Code is usable as a JSON string key without special marshaling.
	code := valerr.CodeStorageError
	if string(code) == "" {
		t.Fatal("code should not be empty")
	}
}
