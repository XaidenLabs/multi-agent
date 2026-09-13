# ADR 0008: Postgres metadata and content-addressed evidence storage

Status: Accepted

Date: 4 September 2026

## Context

The Phase 7 control plane used process memory. That proved the API workflow but could not survive restart, coordinate multiple API or worker instances, enforce evidence retention, or keep confidential evidence outside relational metadata.

The canonical product specification classifies defense metadata and sanitized receipts as public, detailed evidence as tenant confidential, and credentials as secrets that must never enter receipts or logs. It recommends Postgres for relational integrity and S3-compatible object storage with content hashes for artifacts and encrypted evidence.

## Decision

Dadieng stores receipt metadata, immutable Defense Module bundles, replay jobs and reports, and idempotency records in PostgreSQL. A versioned SQL migration establishes uniqueness, foreign-key, state, and lifecycle constraints. The repository remains injectable, and the Phase 7 in-memory implementation remains available for isolated unit tests.

Encrypted evidence bytes are canonicalized and written to a separate content-addressed object store. The relational receipt row contains only the object URI, commitment hash, byte count, and retention timestamps. Filesystem storage is the local durable adapter; it uses confined paths, atomic replacement, owner-only permissions, and SHA-256 verification on every read. A managed S3-compatible adapter can replace it through the same interface.

Receipt deduplication is atomic per tenant. Duplicate uploads with unused object paths are cleaned up, while an exact crash retry never deletes the object already referenced by the accepted receipt. Private evidence reads return a not-found result across tenants and an expired result after retention deletion.

Idempotency records use five-minute ownership leases. Only the owner token may complete or abandon a claim, allowing another instance to reject concurrent duplicates and recover work abandoned by a crashed process. Replay workers claim queued jobs with one atomic database update so only one worker receives a job.

The retention command supports the specification's 30-day maximum and preserves public commitments after deleting confidential bytes. Health checks cover both persistence dependencies without returning connection or filesystem details.

## Consequences

- Accepted receipts, defenses, replay jobs, and idempotent responses survive process restart.
- Multiple API and worker instances can coordinate through shared database constraints.
- Evidence ciphertext does not appear in PostgreSQL, public endpoints, or operational errors.
- Local operation now requires PostgreSQL and a writable private object root.
- The filesystem adapter is appropriate for local and single-host deployment; multi-host deployment requires a shared object-store adapter.
- Phase 9 can add Monad contracts without changing the persistence interfaces established here.
