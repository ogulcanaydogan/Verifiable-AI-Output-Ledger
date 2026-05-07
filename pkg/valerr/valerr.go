// Package valerr defines typed error codes for VAOL API responses.
// Codes are stable identifiers that clients can match programmatically
// without parsing human-readable message strings.
package valerr

// Code is a machine-readable error identifier returned in the "code" field
// of every VAOL error response alongside the human-readable "error" field.
type Code string

const (
	// Request / validation errors (4xx)
	CodeInvalidRequestBody  Code = "VAOL_INVALID_REQUEST_BODY"
	CodeInvalidRecordID     Code = "VAOL_INVALID_RECORD_ID"
	CodeInvalidEnvelope     Code = "VAOL_INVALID_ENVELOPE"
	CodeInvalidVerification Code = "VAOL_INVALID_VERIFICATION_PROFILE"
	CodeProofIDRequired     Code = "VAOL_PROOF_ID_REQUIRED"
	CodeTenantConflict      Code = "VAOL_TENANT_CONFLICT"
	CodeTenantMismatch      Code = "VAOL_TENANT_MISMATCH"
	CodeSubjectMismatch     Code = "VAOL_SUBJECT_MISMATCH"

	// Authorization / policy errors (403 / 409)
	CodePolicyDenied       Code = "VAOL_POLICY_DENIED"
	CodeDuplicateRequestID Code = "VAOL_DUPLICATE_REQUEST_ID"

	// Not-found errors (404)
	CodeRecordNotFound Code = "VAOL_RECORD_NOT_FOUND"
	CodeProofNotFound  Code = "VAOL_PROOF_NOT_FOUND"

	// Internal / infrastructure errors (5xx)
	CodePolicyError          Code = "VAOL_POLICY_ERROR"
	CodeHashError            Code = "VAOL_HASH_ERROR"
	CodeSigningError         Code = "VAOL_SIGNING_ERROR"
	CodeStorageError         Code = "VAOL_STORAGE_ERROR"
	CodeProofGenerationError Code = "VAOL_PROOF_GENERATION_ERROR"
	CodeVerificationError    Code = "VAOL_VERIFICATION_ERROR"
	CodeMarshalError         Code = "VAOL_MARSHAL_ERROR"
	CodeInternalError        Code = "VAOL_INTERNAL_ERROR"
)
