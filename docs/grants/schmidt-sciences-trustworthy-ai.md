# Schmidt Sciences, Science of Trustworthy AI RFP (2026)

> **Program:** Schmidt Sciences, Science of Trustworthy AI
> **URL:** https://schmidtsciences.smapply.io/prog/science_of_trustworthy_ai_rfp_2026/
> **Tier:** 1 (up to $1,000,000, 2 years)
> **Deadline:** 2026-05-17, 11:59 PM AoE
> **Status:** Ready to submit
> **Contact:** trustworthyai@schmidtsciences.org

---

## Proposal Title

Cryptographic Oversight Infrastructure for Frontier AI Systems: Verifiable Audit Trails, Supply Chain Attestation, and Safety Bypass Detection

## Research Summary (300 words)

Current approaches to AI safety focus on model-level interventions: RLHF, constitutional AI, output filtering. These work, up to a point. But when safety mechanisms fail, there's no independent way to verify what happened, when it happened, or whether the model was tampered with before deployment. We lack the infrastructure layer that makes AI system behavior auditable after the fact.

This project builds and validates that infrastructure. We're developing three open source tools that, together, provide end-to-end cryptographic oversight for frontier AI systems:

**Verifiable AI Output Ledger (VAOL)** creates tamper-evident audit trails for AI inference decisions. Every output gets a DSSE signature (Ed25519 or Sigstore keyless), a position in a SHA-256 hash chain, and a slot in an RFC 6962 Merkle tree with verifiable inclusion proofs. If someone alters an audit record, the hash chain breaks. If a record is omitted, the Merkle proof fails. This gives auditors, regulators, and researchers a cryptographic guarantee that the AI system's behavior log hasn't been tampered with.

**LLM-Supply-Chain-Attestation** extends Sigstore and SLSA standards to ML model artifacts. It generates in-toto provenance for model training runs, signs container images, and produces attestations that let you verify a model's full lineage from training data to deployment. Without this, you can't confirm the model running in production is the same one that passed safety evaluations.

**Prompt-Injection-Firewall** detects the 16 attack categories from the OWASP LLM Top 10 that bypass safety mechanisms in deployed systems. It sits at the protocol level, catching injection attempts, jailbreaks, and data exfiltration before they reach the model.

The research agenda is: how do cryptographic verification methods translate to AI system oversight, where do they fail, and what guarantees can they actually provide? We'll publish formal analyses, run adversarial evaluations, and release reproducible benchmarks.

## Aim Alignment

### Aim 1: Characterize misalignment and safety mechanism failures

VAOL's audit trails provide the empirical data needed to study safety failures. When an AI system produces a harmful output despite safety training, VAOL captures the full inference context, including the input, the safety checks that were applied, and the output that was produced. Researchers can query these audit logs to study patterns in safety mechanism failures across thousands of interactions.

Prompt-Injection-Firewall addresses the specific case where misalignment is induced externally. We've catalogued 16 attack categories that cause safety-trained models to behave as if they were never aligned. Our firewall detects these at the protocol level, but the detection data also serves as a research corpus: which safety mechanisms are most fragile? Which attack strategies succeed most often? We'll publish this analysis.

### Aim 3: Oversight for superhuman AI capabilities

The core problem with overseeing AI systems that exceed human capability in specific domains is that human reviewers can't evaluate every output. Cryptographic methods offer a partial solution: you can't verify what a superhuman AI did, but you can verify that the audit trail of what it did hasn't been altered.

VAOL's Merkle tree structure means that any modification to the audit log, even a single bit flip, is detectable. LLM-Supply-Chain-Attestation extends this to the model itself: you can verify that the model in production matches the model that was evaluated. Together, these provide a tamper-evident chain of custody from model training through deployment to runtime behavior.

This doesn't solve the alignment problem, but it solves the accountability problem. If we can't verify what superhuman AI systems actually do (vs. what they're claimed to do), alignment research has no ground truth.

## Proposed Research Activities (2 years)

### Year 1: Infrastructure validation and adversarial testing

**Q1-Q2: Formal security analysis of VAOL's signing pipeline**
- Commission a third-party security audit of the DSSE signing implementation (Ed25519, Sigstore keyless, KMS/HSM backends)
- Formally prove the hash chain integrity properties using TLA+ or Coq
- Publish the audit report and any discovered vulnerabilities
- Deliverable: Security audit report, formal proofs, patched v2.0 release

**Q3-Q4: Adversarial evaluation of supply chain attestation**
- Test LLM-Supply-Chain-Attestation against 12 documented model tampering techniques (weight poisoning, fine-tuning backdoors, quantization attacks, GGUF metadata injection)
- Measure detection rates and false positive rates per attack category
- Build a public benchmark: "How tamper-resistant is your ML pipeline?"
- Deliverable: Published benchmark, dataset of 500+ attack samples, research paper

### Year 2: Integration research and empirical studies

**Q1-Q2: Safety mechanism failure analysis**
- Deploy VAOL audit logging on 3 production AI systems (partner with 2-3 research labs or companies)
- Collect 6 months of audit data, focusing on instances where safety mechanisms produced unexpected outputs
- Analyze patterns: which safety interventions fail most? Under what conditions? Are failures correlated?
- Deliverable: Anonymized dataset, analysis paper, pattern taxonomy

**Q3-Q4: Cryptographic oversight at scale**
- Benchmark VAOL's performance at high throughput (target: 10,000 signed records/second with sub-50ms Merkle proof generation)
- Research the fundamental limits: what oversight guarantees can cryptography provide for AI systems? What can't it provide?
- Publish a position paper on the role of cryptographic infrastructure in AI governance
- Deliverable: Performance benchmarks, limits analysis, position paper

## Budget (Tier 1: $1,000,000 over 2 years)

| Item | Year 1 | Year 2 | Total |
|------|--------|--------|-------|
| Lead researcher (PI, 0.8 FTE) | $90,000 | $90,000 | $180,000 |
| Security engineer (0.5 FTE, audit + adversarial testing) | $60,000 | $60,000 | $120,000 |
| ML engineer (0.5 FTE, model tampering research) | $55,000 | $55,000 | $110,000 |
| Third-party security audit (VAOL signing pipeline) | $80,000 | - | $80,000 |
| Third-party security audit (Supply Chain attestation) | - | $60,000 | $60,000 |
| Compute (GPU for adversarial testing + benchmarks) | $40,000 | $50,000 | $90,000 |
| Cloud infrastructure (CI/CD, testing, artifact storage) | $15,000 | $15,000 | $30,000 |
| Formal verification tooling + licenses | $20,000 | $10,000 | $30,000 |
| Travel (conferences: USENIX Security, IEEE S&P, NeurIPS) | $15,000 | $15,000 | $30,000 |
| Publication costs (open access fees) | $5,000 | $5,000 | $10,000 |
| Participant compensation (safety failure study) | - | $25,000 | $25,000 |
| Equipment and supplies | $10,000 | $5,000 | $15,000 |
| **Subtotal (direct costs)** | **$390,000** | **$390,000** | **$780,000** |
| Indirect costs (10% cap, self-administered) | $39,000 | $39,000 | $78,000 |
| Contingency (unforeseen costs, 5%) | $21,450 | $21,450 | $42,900 |
| **Total** | **$450,450** | **$450,450** | **$900,900** |

Note: This is a Tier 1 proposal. If the review committee sees potential for Tier 2 expansion, we'd extend the safety mechanism failure analysis to 10+ production systems and add a longitudinal study component. That would bring the total to ~$2.5M over 3 years.

## Existing Work

All three projects are open source, actively maintained, and have production-grade CI/CD:

- **VAOL:** 29 releases, 21 CI workflows, OpenSSF Best Practices PASSING (100%), Apache 2.0. Submitted to Sovereign Tech Fund, NLnet, OpenSSF. github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
- **LLM-Supply-Chain-Attestation:** 7 releases, 8 CI workflows, OpenSSF PASSING. Implements Sigstore, in-toto, SLSA. github.com/ogulcanaydogan/LLM-Supply-Chain-Attestation
- **Prompt-Injection-Firewall:** 4 releases, CodeQL in CI, OpenSSF PASSING. Detects OWASP LLM Top 10 categories. github.com/ogulcanaydogan/Prompt-Injection-Firewall

All actions pinned to commit SHAs, SBOM generation on every release, vulnerability scanning in CI.

## Team

**Ogulcan Aydogan (PI):** Software engineer, United Kingdom. Maintains 10 open source AI security projects. Experience: cryptographic signing (DSSE, Sigstore, C2PA), ML pipeline security, supply chain attestation (SLSA, in-toto), production infrastructure (Kubernetes, Terraform). Projects funded/under review by NLnet NGI Zero (9 proposals), Sovereign Tech Fund (3 proposals), OpenAI Cybersecurity Grant (3 proposals), Mozilla Democracy x AI, UK AISI.

The team would expand with the grant: hiring a security engineer and ML engineer to cover the adversarial testing and model tampering research. The PI has experience managing open source projects with multiple contributors and reviewers.

## How Failure Would Look

This is important because the RFP specifically asks us to specify success/failure outcomes.

**Success looks like:** published security audits with actionable findings, formal proofs of hash chain properties, a public benchmark for ML pipeline tampering resistance, and at least one paper accepted at a top security or ML venue.

**Failure looks like:** if we find that cryptographic oversight methods don't provide meaningful guarantees for AI systems, specifically, if the adversarial evaluation shows that supply chain attestation can be trivially bypassed, or if the audit trail's performance overhead makes it impractical for real-time systems. This would be a negative but valuable result, and we'd publish it.

**Partial success looks like:** cryptographic oversight works for some threat models (e.g., external tampering) but not others (e.g., the model itself producing misleading audit data). This is the most likely outcome, and understanding the boundary is the core scientific contribution.

---

## Submission Steps

1. Create account at https://schmidtsciences.smapply.io/
2. Navigate to Science of Trustworthy AI RFP 2026
3. Fill in proposal form using the content above
4. Select Tier 1 ($1M)
5. Attach budget spreadsheet
6. Submit before May 17, 2026, 11:59 PM AoE
7. Update `TRACKING.md` and master tracker

---

## Notes

- Informational webinars: March 11 and April 15, 2026 (attend the April one)
- Indirect costs capped at 10% (we're well under as a solo operation)
- Individual researchers eligible, global participation welcome
- "Non-competitive" proposals: vague methodology, tools without validity arguments, lack of failure criteria. We address all three.
- Decision notification: Summer 2026
- Contact: trustworthyai@schmidtsciences.org
