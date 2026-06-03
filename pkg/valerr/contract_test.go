package valerr_test

import (
	"strings"
	"testing"

	"github.com/ogulcanaydogan/vaol/pkg/valerr"
)

// allCodes enumerates every exported Code constant.
// Update this slice when adding a new code to valerr.go.
var allCodes = []valerr.Code{
	valerr.CodeInvalidRequestBody,
	valerr.CodeInvalidRecordID,
	valerr.CodeInvalidEnvelope,
	valerr.CodeInvalidVerification,
	valerr.CodeProofIDRequired,
	valerr.CodeTenantConflict,
	valerr.CodeTenantMismatch,
	valerr.CodeSubjectMismatch,
	valerr.CodePolicyDenied,
	valerr.CodeDuplicateRequestID,
	valerr.CodeRecordNotFound,
	valerr.CodeProofNotFound,
	valerr.CodePolicyError,
	valerr.CodeHashError,
	valerr.CodeSigningError,
	valerr.CodeStorageError,
	valerr.CodeProofGenerationError,
	valerr.CodeVerificationError,
	valerr.CodeMarshalError,
	valerr.CodeInternalError,
}

// TestContractAllCodesNonEmpty verifies that every exported Code constant
// resolves to a non-empty string — a blank code would be indistinguishable
// from an unset field in a JSON response.
func TestContractAllCodesNonEmpty(t *testing.T) {
	for _, c := range allCodes {
		if string(c) == "" {
			t.Errorf("code at index is empty — every Code must be non-empty")
		}
	}
}

// TestContractNoDuplicateCodeValues verifies that every Code constant has a
// unique underlying string value. Duplicate codes make programmatic error
// handling ambiguous.
func TestContractNoDuplicateCodeValues(t *testing.T) {
	seen := make(map[string]valerr.Code, len(allCodes))
	for _, c := range allCodes {
		if prev, exists := seen[string(c)]; exists {
			t.Errorf("duplicate code value %q: shared by %q and %q", string(c), string(prev), string(c))
		}
		seen[string(c)] = c
	}
}

// TestContractAllCodesHaveVAOLPrefix verifies the naming convention that all
// codes begin with "VAOL_". This ensures codes are unambiguous in multi-service
// error logs and audit records.
func TestContractAllCodesHaveVAOLPrefix(t *testing.T) {
	const prefix = "VAOL_"
	for _, c := range allCodes {
		if !strings.HasPrefix(string(c), prefix) {
			t.Errorf("code %q does not start with %q — all codes must follow the VAOL_ naming convention", string(c), prefix)
		}
	}
}
