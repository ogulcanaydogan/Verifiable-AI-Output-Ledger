# AWS Cloud Credits for Open Source Projects

> **Program:** AWS Promotional Credits for Open Source Projects
> **Apply via:** Email completed form to awsopensourcecredits@amazon.com
> **Application page:** https://pages.awscloud.com/AWS-Credits-for-Open-Source-Projects
> **Amount requested:** $10,000 USD (12 months)
> **Duration:** 1 year (renewable)
> **Type:** Promotional credits for CI/CD, testing, benchmarks
> **Status:** Ready to submit
> **Deadline:** Rolling (reviewed monthly)

---

## Application Email

**To:** awsopensourcecredits@amazon.com
**Subject:** AWS Open Source Credits Application: AI Security Infrastructure (10 MIT/Apache-licensed projects)

---

Hi,

I'm applying for AWS promotional credits for a portfolio of 10 open source AI security and governance projects. All are OSI-licensed (MIT or Apache 2.0), maintained by me as a solo developer, and have no commercial backing or VC funding.

### What we build

These projects provide security, compliance, and observability infrastructure for AI/LLM systems:

**Core projects (most AWS-intensive):**

- **Verifiable AI Output Ledger** (Go, Apache 2.0) creates tamper-evident audit trails for AI decisions using DSSE signing, SHA-256 hash chains, and RFC 6962 Merkle trees. 29 releases, 21 CI workflows. Repo: github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger

- **AI-Provenance-Tracker** (Python/Node.js, MIT) detects AI-generated content across text, images, audio, and video with explainable scoring. Multi-model consensus engine. 20 CI workflows. Repo: github.com/ogulcanaydogan/AI-Provenance-Tracker

- **Sovereign-RAG-Gateway** (Python, MIT) is a policy-first RAG governance layer with PHI/PII redaction, OPA enforcement, and audit logging. 19 releases, 11 CI workflows. Repo: github.com/ogulcanaydogan/Sovereign-RAG-Gateway

**Additional projects:**

- **LLM-Supply-Chain-Attestation** (Go, Apache 2.0), Sigstore/SLSA signing for ML models. 7 releases.
- **Prompt-Injection-Firewall** (Go, Apache 2.0), OWASP LLM Top 10 detection. 4 releases.
- **LLM-SLO-eBPF-Toolkit** (Go, MIT), kernel-level observability for LLM SLOs. 7 releases, 11 CI workflows.
- **AI-Model-Card-Generator** (Go, MIT), automated model cards for HuggingFace/W&B/MLflow. 4 releases.
- **AI-Regulation-Compliance-Scanner** (Python, MIT), EU AI Act and NIST AI RMF scanning. 2 releases.
- **LLM-Cost-Guardian** (Go, MIT), multi-provider cost tracking for LLM inference.
- **MMSAFE-Bench** (Python, MIT), multi-modal safety evaluation across 20 hazard categories.

### How we'd use the credits

**CI/CD and automated testing ($4,000/year):**
All 10 repos run GitHub Actions, but integration tests that require actual AWS services (S3 for artifact storage, SQS for event queues, DynamoDB for state) currently run only locally. Credits would let us add cloud integration tests to CI. We run about 85 CI workflows across the portfolio.

**ML model training and benchmarks ($3,500/year):**
AI-Provenance-Tracker trains detection classifiers for text, image, audio, and video. We currently rely on donated GPU time, which is unreliable. We'd use SageMaker or EC2 GPU instances (g4dn.xlarge) for nightly benchmark runs and periodic model retraining. The detection benchmark covers 4 modalities and we're expanding to 5 languages (Arabic, Farsi, Russian, Mandarin, Spanish).

**Artifact storage and distribution ($1,500/year):**
S3 for storing signed release artifacts, SBOMs, and SLSA provenance attestations. LLM-Supply-Chain-Attestation generates in-toto attestations for every release; storing and serving these from S3 with CloudFront would make verification faster for downstream users.

**Container image hosting ($1,000/year):**
ECR for pre-built Docker images of Sovereign-RAG-Gateway and AI-Provenance-Tracker. Users in bandwidth-constrained environments (the primary audience for Provenance Tracker is journalists in press-restricted countries) need reliable container registry access.

### Project health

- 10 repos, all publicly available on GitHub under github.com/ogulcanaydogan
- 85+ CI/CD workflows across the portfolio (GitHub Actions, SHA-pinned)
- All actions pinned to commit SHAs, no mutable tags
- Every repo has SECURITY.md, SBOM generation, and vulnerability scanning
- 5 repos have OpenSSF Best Practices badges (all PASSING at 100%)
- OpenSSF Scorecard workflows running on all 10 repos
- All 10 repos registered on FLOSS/fund and dir.floss.fund
- Funded/applied: NLnet NGI Zero (9 apps), Sovereign Tech Fund (3 apps), OpenAI Cybersecurity Grant (3 apps), Mozilla Democracy x AI, GitHub Secure OSS Fund, LTFF

### About me

I'm a software engineer based in the United Kingdom. I maintain all 10 projects as a solo developer, with no commercial entity or VC behind them. The projects exist to fill gaps in open source AI security tooling that commercial products don't address, particularly for users in regulated industries and press-restricted environments.

Repository index: github.com/ogulcanaydogan
Contact: security@ogulcanaydogan.com
Location: United Kingdom

Best regards,
Ogulcan Aydogan

---

## Submission Steps

1. Visit https://pages.awscloud.com/AWS-Credits-for-Open-Source-Projects (redirects to blog post)
2. Download the application form if available on the page
3. If no downloadable form exists, send the email above directly to awsopensourcecredits@amazon.com
4. Include links to all 10 repositories
5. Wait for monthly review cycle (expect 2-4 weeks for response)
6. If approved, credits will be applied to your AWS account
7. Credits expire after 1 year; re-apply annually
8. Update `TRACKING.md` and master tracker with submission date

---

## Notes

- AWS reviews on a monthly cycle, rolling deadline
- Credits cover 200+ AWS services (EC2, S3, SageMaker, Lambda, etc.)
- Credits do NOT cover: All Upfront Reserved Instances, AWS Marketplace 3rd-party software, Route 53 domains
- Need active AWS account with valid payment method
- No retroactive application to past charges
- Program favors: OSI license (all ours qualify), not VC-funded (we're not), not single-vendor (solo maintainer, not a company), active maintenance (all repos have recent commits)
- Previously funded 200+ projects since 2019, including Apache Foundation, Linux Foundation, Ruby Central
