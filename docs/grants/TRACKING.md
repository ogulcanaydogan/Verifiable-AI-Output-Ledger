# VAOL Security Audit & Grant Applications, Tracking

> Central tracking hub for all free/funded security audit and grant applications.
> Last updated: 2026-03-13

---

## Summary

| # | Program | Amount | Deadline | Status | Follow-up Date |
|---|---------|--------|----------|--------|----------------|
| 1 | OpenSSF Best Practices Badge | Free (credibility) | Rolling | **Pending submission** | - |
| 2 | OpenSSF Scorecard | Free (CI action) | N/A | **Workflow added** | - |
| 3 | Huntr Bug Bounty | Free pipeline | Rolling | **Pending registration** | - |
| 4 | GitHub Secure Open Source Fund | $10K + $10K Azure | Rolling | **Application ready** | - |
| 5 | Sovereign Tech Resilience Program | EUR 50,000+ | **2026-03-25** | **Application ready** | 2026-04-08 |
| 6 | AISI Challenge Fund (UK) | GBP 50K–200K | **2026-03-31** | **Application ready** | 2026-04-14 |
| 7 | NLnet NGI Zero Commons Fund | EUR 5K–50K | **2026-04-01** | **Application ready** | 2026-04-15 |
| 8 | OSTIF | Free audit | Rolling | **Outreach email ready** | - |
| 9 | OpenAI Cybersecurity Grant | $1M + $10M API | Rolling | **Application ready** | - |
| 10 | Sovereign Tech Fund (main program) | EUR 50,000+ | Rolling | Queued (April) | - |

---

## Phase 1: Quick Wins (March 13–14)

### 1. OpenSSF Best Practices Badge
- **URL:** https://www.bestpractices.dev/
- **Cost:** Free
- **What we get:** CII badge for README, credibility for all other applications
- **Guide:** [openssf-badge-guide.md](openssf-badge-guide.md)
- **Status:** Pending submission
- **Notes:** VAOL already has SECURITY.md, CONTRIBUTING.md, CI, tests, license, so it should achieve passing level quickly

### 2. OpenSSF Scorecard
- **URL:** https://securityscorecards.dev/
- **Cost:** Free
- **What we get:** Security health score, SARIF reports in GitHub Security tab
- **Status:** Workflow added to `.github/workflows/scorecard.yml`
- **Notes:** Will run on next push to main. Results published to OpenSSF dashboard automatically.

### 3. Huntr Registration
- **URL:** https://huntr.com/
- **Cost:** Free
- **What we get:** Free AI/ML-focused bug bounty pipeline, community security testing
- **Guide:** [huntr-registration.md](huntr-registration.md)
- **Status:** Pending registration

### 4. GitHub Secure Open Source Fund
- **URL:** https://resources.github.com/github-secure-open-source-fund/
- **Cost:** Free to apply
- **What we get:** $10,000 direct funding + $10,000 Azure credits + 3-week security program
- **Application:** [github-secure-oss-fund.md](github-secure-oss-fund.md)
- **Status:** Application text ready

---

## Phase 2: Deadline Applications (March 15–31)

### 5. Sovereign Tech Resilience Program
- **URL:** https://www.sovereign.tech/programs/fund
- **Amount:** EUR 50,000+
- **Deadline:** **2026-03-25**
- **Follow-up:** 2026-04-08
- **Application:** [sovereign-tech-fund.md](sovereign-tech-fund.md)
- **Frame:** Digital sovereignty infrastructure for AI governance, EU AI Act compliance tooling
- **Status:** Application text ready

### 6. AISI Challenge Fund (UK)
- **URL:** https://find-government-grants.service.gov.uk/grants/aisi-challenge-fund-1
- **Amount:** GBP 50,000–200,000
- **Deadline:** **2026-03-31**
- **Follow-up:** 2026-04-14
- **Application:** [aisi-challenge-fund.md](aisi-challenge-fund.md)
- **Frame:** AI safety infrastructure, tamper-evident records for regulated AI environments
- **Status:** Application text ready

### 7. NLnet NGI Zero Commons Fund (BEST FIT)
- **URL:** https://nlnet.nl/propose/
- **Amount:** EUR 5,000–50,000
- **Deadline:** **2026-04-01**
- **Follow-up:** 2026-04-15
- **Application:** [nlnet-ngi-zero.md](nlnet-ngi-zero.md)
- **Frame:** Open source cryptographic infrastructure for AI accountability. EU AI Act/GDPR.
- **Bonus:** Grantees automatically receive security audit support, mentoring, testing
- **Status:** Application text ready

---

## Phase 3: Rolling Applications (April 1–15)

### 8. OSTIF
- **Contact:** amir@ostif.org
- **What we get:** Free security audit (funded by Google, etc.)
- **Outreach:** [ostif-outreach.md](ostif-outreach.md)
- **Status:** Outreach email ready

### 9. OpenAI Cybersecurity Grant
- **URL:** https://openai.com/form/cybersecurity-grant-program
- **Amount:** $1M grants + $10M API credits pool
- **Application:** [openai-cybersecurity-grant.md](openai-cybersecurity-grant.md)
- **Status:** Application text ready

### 10. Sovereign Tech Fund (Main Program)
- **URL:** https://www.sovereign.tech/programs/fund
- **Amount:** EUR 50,000+
- **Status:** Queued, submit in April after Resilience Program response

---

## Watch List (No Action Now)

| Program | Notes | Check Date |
|---------|-------|------------|
| Alpha-Omega (OpenSSF) | Projects are nominated, no public application. Build adoption first. | 2026-Q3 |
| Alan Turing Institute Fellowship | Closed, watch for 2027 cycle | 2026-09 |
| Innovate UK Cyber Local | Closed, watch for next cycle | 2026-06 |
| Mozilla Democracy x AI | Up to $50K, check for new cohort | 2026-06 |

---

## VAOL Repo Materials Referenced Across Applications

| Document | Purpose |
|----------|---------|
| `README.md` | Project overview, architecture diagrams |
| `docs/threat-model.md` | 16 attack vectors modelled |
| `docs/crypto-design.md` | DSSE, RFC 6962, RFC 8785, Ed25519/Sigstore/KMS |
| `docs/architecture.md` | System design (13+ packages, 4 binaries, 2 SDKs) |
| `docs/external-audit-readiness.md` | Audit preparation status, evidence package |
| `GOVERNANCE.md` | Maintainer model, security review gates |
| `SECURITY.md` | Vulnerability disclosure policy, response SLAs |
| `CHANGELOG.md` | Release history (v0.1.0 through v0.2.28) |
| `.github/workflows/ci.yml` | CI with security scanning, SBOM |
| `.github/workflows/scorecard.yml` | OpenSSF Scorecard (new) |

---

## Post-Submission Checklist

For each submitted application:
- [ ] Record submission date and confirmation number/email
- [ ] Set calendar reminder for follow-up date (2 weeks after deadline)
- [ ] Update this tracking document with actual status
- [ ] Save any additional information requests
- [ ] Update README.md with earned badges (OpenSSF Badge, Scorecard)
