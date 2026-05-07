# Roadmap

## Current: v0.2.28

Append-only cryptographic audit ledger for LLM inferences using DSSE envelopes, RFC 6962 Merkle trees, OPA policy-as-code, and JWT multi-tenant auth. Persistent Merkle leaves, writer fencing, snapshot restore, and audit-pack tooling all shipped.

---

## v0.2.30 — HA + DR Hardening (May 2026)

- [ ] HA sequencer: leader election with lease-based fencing across replicas
- [ ] DR playbook: documented + tested recovery from snapshot, including cross-region restore
- [ ] Control matrix: map each ledger invariant to a testable CI assertion
- [ ] Structured error taxonomy: typed error codes replacing opaque HTTP 500s

**Target branch**: `feature/v0.2.30-ha`

---

## v1.0.0 — External Audit Gate (Q2 2026)

- [ ] External audit gate: RFP/SOW-driven third-party verifiability check
- [ ] Multi-region docs with region-failover runbook
- [ ] Python SDK GA (currently v0.x, needs 1.0 stability guarantee + full test coverage)
- [ ] Public benchmark: write throughput, proof generation latency, verification cost

**This is the primary near-term milestone. Most release-blockers are documentation and CI gates, not code.**

---

## v1.1.0 — SDK Ecosystem (Q3 2026)

- [ ] TypeScript/JavaScript SDK (parity with Python SDK)
- [ ] Multi-tenant federation: cross-tenant cross-ledger proof verification
- [ ] GraphQL subscription for real-time leaf append events
- [ ] OpenTelemetry metrics exporter (latency histograms, proof generation p99)

---

## Known issues / backlog

See [open issues](https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/issues).
