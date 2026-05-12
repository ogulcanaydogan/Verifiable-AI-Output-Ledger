# VAOL Control Matrix

Maps each ledger integrity invariant to the CI assertion that enforces it.

CI jobs are defined in `.github/workflows/ci.yml`. All jobs run on every PR and on every push to `main`.

---

## Invariant 1 — Hash-chain continuity

**Statement**: `previous_record_hash` of record `N` equals `record_hash` of record `N-1`. No gaps or reorders are permitted.

| Assertion | CI job | Test / script |
|---|---|---|
| Broken hash link detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_BrokenChainLink` |
| Hash-chain gap detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ChainGap` |
| Out-of-order record rejected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ChainReorder` |
| Post-hash field mutation detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ChainRecordTamperedAfterHash` |

---

## Invariant 2 — DSSE signature integrity

**Statement**: Every record is wrapped in a DSSE envelope; any modification to fields covered by the signature must be detectable.

| Assertion | CI job | Test / script |
|---|---|---|
| Wrong signing key rejected | Test (E2E + Tamper) | `tests/tamper/TestTamper_SignWithWrongKey` |
| Corrupted signature bytes rejected | Test (E2E + Tamper) | `tests/tamper/TestTamper_CorruptSignature` |
| Missing signatures rejected | Test (E2E + Tamper) | `tests/tamper/TestTamper_RemoveSignatures` |

---

## Invariant 3 — Field-level tamper detection

**Statement**: Modifications to any auditable field (`model_name`, `output_hash`, `prompt_hash`, `policy_decision`, `tenant_id`, `timestamp`, `record_hash`) are detected before verification passes.

| Assertion | CI job | Test / script |
|---|---|---|
| `model_name` mutation detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ModifyModelName` |
| `output_hash` mutation detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ModifyOutputHash` |
| `prompt_hash` mutation detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ModifyPromptHash` |
| `policy_decision` mutation detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ModifyPolicyDecision` |
| `tenant_id` mutation detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ModifyTenantID` |
| `timestamp` mutation detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ModifyTimestamp` |
| Incorrect `record_hash` detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_WrongRecordHash` |

---

## Invariant 4 — Merkle inclusion

**Statement**: Every appended record has a valid Merkle inclusion proof against the current tree root.

| Assertion | CI job | Test / script |
|---|---|---|
| Wrong data fails inclusion proof | Test (E2E + Tamper) | `tests/tamper/TestTamper_MerkleInclusionWrongData` |
| Modified proof rejected | Test (E2E + Tamper) | `tests/tamper/TestTamper_MerkleInclusionModifiedProof` |
| Root mismatch detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_MerkleRootMismatch` |
| Inclusion proof correct (unit) | Test (Go Full) | `pkg/merkle/TestInclusionProofMultipleLeaves` |
| Inclusion proof rejects wrong data (unit) | Test (Go Full) | `pkg/merkle/TestVerifyInclusionRejectsWrongData` |

---

## Invariant 5 — Merkle tree-size monotonicity

**Statement**: The Merkle tree `tree_size` never decreases across appends.

| Assertion | CI job | Test / script |
|---|---|---|
| Tree-size regression detected | Test (E2E + Tamper) | `tests/tamper/TestTamper_MerkleTreeSizeRegression` |
| Consistency proof valid after append | Test (E2E + Tamper) | `tests/tamper/TestTamper_MerkleConsistencyAfterAppend` |
| Consistency proof (unit) | Test (Go Full) | `pkg/merkle/TestConsistencyProof` |

---

## Invariant 6 — Replay prevention

**Statement**: A duplicate record (same `record_hash`) is rejected; the append sequence is idempotency-safe at the content level.

| Assertion | CI job | Test / script |
|---|---|---|
| Duplicate record rejected | Test (E2E + Tamper) | `tests/tamper/TestTamper_ReplayDuplicateRecord` |

---

## Invariant 7 — Schema validity

**Statement**: Every record must conform to the canonical schema before it is accepted by the ingest path.

| Assertion | CI job | Test / script |
|---|---|---|
| Valid record accepted | Test (Go Full) | `pkg/record/TestValidateValidRecord` |
| Schema version enforced | Test (Go Full) | `pkg/record/TestValidateSchemaVersion` |
| Required field presence enforced | Test (Go Full) | `pkg/record/TestValidateMissing*` (8 cases) |
| Hash format validated | Test (Go Full) | `pkg/record/TestValidateInvalidHashFormat` |
| Policy decision enum enforced | Test (Go Full) | `pkg/record/TestValidateInvalidPolicyDecision` |
| Output mode consistency enforced | Test (Go Full) | `pkg/record/TestValidateEncryptedMode*`, `TestValidatePlaintext*` |

---

## Invariant 8 — Cryptographic correctness

**Statement**: SHA-256 leaf hashes and Merkle root computations are deterministic and match the RFC 6962 construction.

| Assertion | CI job | Test / script |
|---|---|---|
| Leaf hash determinism | Test (Go Full) | `pkg/merkle/TestLeafHash`, `TestRootDeterministic` |
| Root changes on new leaf | Test (Go Full) | `pkg/merkle/TestRootChangesWithNewLeaf` |
| Different data produces different root | Test (Go Full) | `pkg/merkle/TestRootDifferentData` |
| Benchmarks (regression budget) | Benchmarks | `go test -bench=. pkg/merkle/...` — p99 gate via `Bench (Startup Restore Gate)` |

---

## Invariant 9 — OPA policy consistency

**Statement**: The OPA Rego policies compile and all unit tests pass; no policy change silently drops a required rule.

| Assertion | CI job | Test / script |
|---|---|---|
| Policy unit tests pass | Test (OPA Policies) | `opa test policies/ -v` |

---

## Gap register (v0.2.30 targets)

| Gap | Planned fix | Milestone |
|---|---|---|
| No CI assertion for HA sequencer leader-election fencing | Unit test for `pkg/ingest` writer-fence invariant | v0.2.30 |
| No cross-region consistency test | DR playbook integration test | v0.2.30 |
| Structured error taxonomy not validated by CI | Add `pkg/valerr` contract test | v0.2.30 |
