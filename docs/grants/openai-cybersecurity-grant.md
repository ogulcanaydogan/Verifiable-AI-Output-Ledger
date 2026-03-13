# OpenAI Cybersecurity Grant, Application

> **URL:** https://openai.com/form/cybersecurity-grant-program
> **Amount:** $1M grants pool + $10M API credits pool
> **Deadline:** Rolling
> **Frame:** Cryptographic verification infrastructure for AI output integrity

---

## Application Form Responses

### Project Title

VAOL: Cryptographic Verification Infrastructure for AI Output Integrity

### Project Description

VAOL (Verifiable AI Output Ledger) is an open source cryptographic audit ledger that creates tamper-evident records of AI inference decisions. It addresses a fundamental cybersecurity gap: organisations deploying AI systems have no standardised way to detect if AI outputs have been manipulated between generation and consumption.

VAOL provides layered verification through DSSE digital signatures (Ed25519, Sigstore, KMS/HSM), SHA-256 hash chains with RFC 8785 canonicalization, and RFC 6962 Merkle trees with inclusion/consistency proofs. Policy-as-code enforcement via OPA/Rego ensures governance rules are applied at decision time with fail-closed defaults.

The system integrates with OpenAI's API through both a Python SDK wrapper (`vaol.instrument_openai()`) and an OpenAI-compatible transparent proxy that logs every API call to the verifiable ledger without code changes.

### How does this project advance AI cybersecurity?

**1. AI output integrity verification:**
Without cryptographic signing, AI outputs can be silently modified between the API response and downstream consumption. VAOL creates a signed record at the moment of inference, allowing any party to later verify the output hasn't been altered. This is critical for AI deployments in healthcare (diagnostic recommendations), finance (risk assessments), and legal (document analysis).

**2. Tamper-evident audit trails:**
Application logs can be modified or deleted. VAOL's hash chains (SHA-256 with RFC 8785 canonicalization) and Merkle trees (RFC 6962) make any record insertion, deletion, or reordering cryptographically detectable. Auditors can verify completeness using consistency proofs.

**3. Policy enforcement evidence:**
OPA/Rego policies evaluated at decision time create verifiable proof that governance rules were applied to every AI interaction. This goes beyond retrospective compliance; it proves policy compliance existed at the moment of inference.

**4. Zero-trust verification:**
Clients verify signatures and Merkle proofs entirely offline using the CLI or SDK. No need to trust the server, the AI provider, or any intermediary.

**5. Supply chain security for AI decisions:**
Similar to how Sigstore provides supply chain security for software artifacts, VAOL provides supply chain security for AI decision records, proving the complete chain from prompt to output to policy evaluation.

### Specific use of funding

**Security/cryptography audit ($30,000–50,000):**
An independent security audit is the v1.0.0 release gate. The audit scope covers:
- DSSE signing pipeline (Ed25519, Sigstore keyless, KMS backends)
- RFC 6962 Merkle tree implementation
- Hash chain integrity (SHA-256, JCS canonicalization)
- Multi-tenant authorisation (JWT/OIDC, tenant isolation)
- OPA policy engine integration (fail-closed enforcement)

**Fuzzing infrastructure ($5,000–10,000):**
Extended fuzzing for cryptographic components using API credits for:
- AI-assisted fuzzing of signing and verification paths
- LLM-generated test cases for edge conditions in canonicalization and proof verification
- Automated vulnerability pattern detection in the codebase

**OpenAI API integration hardening ($5,000–10,000):**
- Enhanced OpenAI proxy with streaming support and function call recording
- Robustness testing with diverse API response patterns
- Performance benchmarking at scale with real API traffic patterns

### Specific use of API credits

- **AI-assisted security testing:** Use GPT-4 to generate adversarial test cases targeting the verification pipeline
- **Fuzz generation:** LLM-generated malformed DSSE envelopes, Merkle proofs, and decision records
- **Documentation review:** Automated analysis of threat model completeness and cryptographic design review
- **Integration testing:** High-volume testing of the OpenAI proxy and SDK instrumentation under realistic traffic

### Current security measures

- Threat model covering 16 attack vectors with mitigations
- Cryptographic design document specifying all operations against RFCs
- CI pipeline: gosec, govulncheck, Trivy, Go race detector, E2E tamper detection tests
- SBOM generation (Anchore SPDX)
- All GitHub Actions pinned to commit SHAs
- Security-sensitive code paths require 2+ reviewer approvals
- Formal vulnerability disclosure policy with 48h/5-day/10-day SLAs
- OpenSSF Scorecard in CI
- Audit readiness package with control matrix and SOW template

### Repository

https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger

### License

Apache License 2.0

### OpenAI Integration Details

VAOL provides two integration paths for OpenAI:

**1. Python SDK instrumentation:**
```python
from openai import OpenAI
import vaol

client = OpenAI()
vaol_client = vaol.VAOLClient("http://localhost:8080")
wrapped = vaol.instrument_openai(client, vaol_client, tenant_id="my-org")
# Every chat.completions.create() now emits a signed DecisionRecord
```

**2. OpenAI-compatible proxy:**
```bash
./bin/vaol-proxy --upstream https://api.openai.com --vaol-server http://localhost:8080
export OPENAI_BASE_URL=http://localhost:8443/v1
# All OpenAI API calls transparently logged to VAOL
```

Both paths capture model identity, prompt hash, output hash, policy context, and create a DSSE-signed record anchored in the Merkle tree.

---

## Supporting Materials Checklist

- [ ] Repository: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
- [ ] README.md: project overview, OpenAI integration examples
- [ ] docs/threat-model.md: 16 attack vectors
- [ ] docs/crypto-design.md: cryptographic specification
- [ ] docs/architecture.md: system design including proxy
- [ ] SECURITY.md: vulnerability disclosure policy
- [ ] sdk/python/: Python SDK with OpenAI instrumentation
- [ ] cmd/vaol-proxy/: OpenAI-compatible proxy source

---

## Submission Steps

1. Navigate to https://openai.com/form/cybersecurity-grant-program
2. Fill in the application form using responses above
3. Link the repository and highlight the OpenAI integration paths
4. Submit
5. Record confirmation and update `TRACKING.md`
