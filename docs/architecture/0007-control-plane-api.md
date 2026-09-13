# ADR 0007: Framework-light control-plane API

Status: Accepted

Date: 3 September 2026

## Context

Phases 1–6 established local enforcement, portable Defense Modules, privacy-safe Threat Receipts, and deterministic replay. Dadieng now needs a network boundary that preserves those invariants while keeping persistence and chain publication replaceable in later phases.

## Decision

Dadieng exposes a versioned `/v1` Fetch-compatible application with a small Node HTTP adapter. Business workflows live in `ControlPlaneService`; state lives behind `ControlPlaneRepository`. Phase 7 ships an in-memory repository only.

Writes authenticate a scoped machine principal and require an idempotency key. The idempotency record is isolated by tenant, subject, method, and path; reusing a key with another body is rejected. Public and private traffic share a fixed-window rate-limit boundary. All errors use RFC 9457-style `application/problem+json` documents with a request ID and no raw exception content.

Receipt intake revalidates the public-safety rules and verifies the exact encrypted evidence commitment before storage. Public reads return the receipt but never its encrypted evidence envelope. Defense versions are verified against every committed artifact hash and become immutable once accepted. Replay requests are queued, and a worker verifies the resulting report against the exact stored bundle before marking it complete.

The chain result on receipt creation is explicitly `not-requested` or `awaiting-adapter`; Phase 7 does not fabricate a Monad transaction or operation ID.

## Consequences

- The complete workflow can be tested without a live database, object store, chain, or external replay service.
- The HTTP contract is independent of the Node adapter and can later be hosted behind another runtime.
- In-memory state is lost on restart and is unsuitable for production.
- API keys are a Phase 7 machine-auth adapter. User sessions and wallet-signature adapters can implement the same authenticator boundary later.
- Durable idempotency, tenant isolation at the database layer, evidence object storage, and worker claiming belong to Phase 8.
