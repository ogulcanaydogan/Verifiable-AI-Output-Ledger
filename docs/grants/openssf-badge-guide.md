# OpenSSF Best Practices Badge, Submission Guide

> **URL:** https://www.bestpractices.dev/
> **Time:** ~30 minutes
> **Cost:** Free
> **What you get:** CII Best Practices badge for README + credibility for all other grant applications

---

## Pre-Submission Checklist

VAOL already satisfies most passing-level criteria. Verify these before starting:

| Criterion | VAOL Status | Evidence |
|-----------|-------------|----------|
| OSS license (approved by OSI) | Apache 2.0 | `LICENSE` |
| Project website with basic info | GitHub README | `README.md` |
| Version control (public repo) | GitHub | `github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger` |
| Unique version numbering | SemVer | `CHANGELOG.md` (v0.1.0 → v0.2.28) |
| Release notes | Per-version changelogs | `CHANGELOG.md`, `docs/releases/` |
| Bug reporting process | GitHub Issues | `.github/ISSUE_TEMPLATE/` or Issues tab |
| Build system | Makefile + go build | `Makefile`, `go.mod` |
| Automated test suite | Go tests, Python pytest, TS npm test | `.github/workflows/ci.yml` |
| New functionality tested | CI enforces test coverage | CI jobs: test-go, test-python, test-typescript |
| Warning flags enabled | golangci-lint, ruff, mypy, ESLint | CI lint jobs |
| HTTPS for project sites | GitHub uses HTTPS | Default |
| English documentation | All docs in English | `docs/` |
| Vulnerability reporting process | Private disclosure policy | `SECURITY.md` |
| Working build system | CI green | `.github/workflows/ci.yml` |
| Security scanning in CI | gosec, govulncheck, Trivy | CI `security` job |
| SBOM generation | Anchore SPDX | CI `sbom` job |

---

## Step-by-Step Submission

### 1. Go to bestpractices.dev
Navigate to https://www.bestpractices.dev/ and click **"Get Your Badge Now"**.

### 2. Sign in with GitHub
Use your GitHub account (`ogulcanaydogan`).

### 3. Add your project
Enter the repository URL:
```
https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
```

### 4. Fill out the form

The form has sections. Here's how to answer each for VAOL:

#### Basics
- **Project name:** VAOL (Verifiable AI Output Ledger)
- **Description:** Cryptographically verifiable, append-only audit ledger for AI/LLM inference decisions. DSSE envelopes, RFC 6962 Merkle trees, OPA policy-as-code, multi-tenant JWT authentication.
- **Project URL:** https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
- **License:** Apache-2.0
- **Documentation URL:** https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/tree/main/docs

#### Change Control
- **Public version control:** Yes (GitHub)
- **Unique version numbering:** Yes (SemVer, see CHANGELOG.md)
- **Release notes:** Yes (CHANGELOG.md with per-version entries)

#### Reporting
- **Bug reporting process:** Yes (GitHub Issues)
- **Vulnerability reporting process:** Yes → point to `SECURITY.md`
  - Private email: security@yapay.ai
  - Response SLAs documented

#### Quality
- **Working build system:** Yes (Makefile, `go build`)
- **Automated test suite:** Yes (Go race-detector tests, Python pytest, TypeScript npm test, OPA policy tests, E2E tamper tests)
- **New functionality testing policy:** Yes (CI enforces tests; GOVERNANCE.md requires tests for PRs)
- **Test coverage:** State current coverage percentage (run `go test -cover ./...` to get exact number)

#### Security
- **Secure development knowledge:** Yes (threat model, crypto design doc, security review gates)
- **Use basic good cryptographic practices:** Yes (Ed25519/RFC 8032, DSSE, RFC 6962, RFC 8785 JCS, SHA-256)
- **No unpatched vulnerabilities of medium or higher severity:** Yes (govulncheck + Trivy in CI)
- **Static analysis:** Yes (gosec, golangci-lint, ruff, mypy)
- **Vulnerability reporting process:** Already answered above

#### Analysis
- **Static analysis in CI:** Yes → gosec, govulncheck, golangci-lint
- **Dynamic analysis:** Yes → go test -race (race detector), tamper detection tests

### 5. Submit and get badge

After filling out all fields, submit. You'll get a badge URL like:
```
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/XXXXX/badge)](https://www.bestpractices.dev/projects/XXXXX)
```

### 6. Add badge to README.md

Add to the badge line in README.md (after the existing badges):
```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/XXXXX/badge)](https://www.bestpractices.dev/projects/XXXXX)
```

---

## Tips for Higher Levels (Silver/Gold)

After passing, you can work toward Silver and Gold levels:

- **Silver:** Requires code review policy (GOVERNANCE.md covers this), multiple contributors, and bus factor >1
- **Gold:** Requires reproducible builds, formal security audit (which is what the grant applications fund)

The passing badge is sufficient for now and strengthens all other grant applications.
