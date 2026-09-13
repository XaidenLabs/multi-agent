# Architecture Decision 0006: Deterministic replay reports

Status: Accepted

## Decision

Dadieng replay verifies a complete Defense Module bundle before executing every committed attack and legitimate-control case through the same deterministic evaluator. The worker emits `dadieng.replay-report.v2`, containing artifact commitments, environment identity, per-case assertions, effectiveness and utility summaries, latency percentiles, candidate thresholds, and a hash over the complete report.

Fixture bodies never enter the report. Case identifiers, expected and actual outcomes, reason codes, measurements, and content hashes in the committed suite provide reproducibility without republishing hostile or private input.

## Reproducibility boundary

A report records the worker image digest, dependency-lock hash, runtime identifier, seed, and explicit network/filesystem/clock policy. Runtime services for run IDs, timestamps, and measurements are injectable, allowing byte-for-byte reproduction in a declared deterministic environment. Real latency measurements may naturally differ across machines; validators compare exact artifacts and assertions and publish their own report commitment.

The committed reference report deliberately uses injected fixture measurements to test deterministic calculations and must not be presented as a hardware benchmark. Production performance claims require wall-clock measurement in an independently identified worker environment.

The report hash excludes only its own `reportHash` field. Verification recomputes the hash, validates internal case/summary/threshold consistency, recalculates latency percentiles, and can bind the report to a supplied Defense Module bundle.

## Isolation boundary

The Phase 6 local worker runs only the declarative `dadieng-rules` runtime. The verified module has no network, filesystem, clock, or credential API and cannot execute submitted source code. The report environment records `network: none`, `filesystem: read-only`, and `clock: deterministic`.

This is a constrained evaluator, not a general-purpose process sandbox. TypeScript and WebAssembly modules remain rejected. Supporting them requires a later hardened worker with enforced CPU, memory, time, filesystem, and network limits.

## Release policy

Candidate defaults follow the product specification: at least 95% attack success, at least 95% legitimate-control success, and P95 module latency no greater than 50 ms. Reports record actual values and never claim universal safety. Stable promotion and independent signatures belong to later validator and protocol phases.
