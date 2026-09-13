# Dadieng control plane

The control plane accepts sanitized receipts, registers immutable Defense Module versions, queues replay jobs and Monad transactions, and exposes privacy-safe public results.

## Run locally

```bash
export DADIENG_API_KEY="replace-with-a-long-random-key"
export DATABASE_URL="postgresql://dadieng:replace-me@127.0.0.1:5432/dadieng"
export DADIENG_OBJECT_ROOT="./.dadieng/objects"
pnpm db:migrate
pnpm api:start
```

The server binds to `127.0.0.1:3001` by default. Set `PORT` to use another local port. The startup command deliberately refuses to create or print a default credential.

Every write requires `Authorization: Bearer <key>`, the corresponding scope, `Content-Type: application/json`, and an `Idempotency-Key`. Errors use `application/problem+json`, and every response carries a `requestId`.

## API endpoints

| Method | Path | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | Public, rate-limited | Readiness check |
| `POST` | `/v1/receipts` | `receipts:write` | Verify and store a sanitized receipt plus encrypted evidence |
| `GET` | `/v1/receipts/{id}` | Public, rate-limited | Read only the privacy-safe receipt and resolution state |
| `POST` | `/v1/defenses` | `defenses:write` | Register a Defense Module identity and author |
| `POST` | `/v1/defenses/{id}/versions` | `defenses:write` | Verify and publish an immutable candidate bundle |
| `POST` | `/v1/replays` | `replays:write` | Queue a deterministic replay against an exact version |
| `GET` | `/v1/replays/{id}` | Public, rate-limited | Read replay state and its verified report when complete |
| `GET` | `/v1/operations/{id}` | Public, rate-limited | Read a chain operation's stage, hash, confirmations, and safe-retry state |
| `GET` | `/v1/validators/jobs` | `validators:read` | List open or validator-owned independent validation jobs |
| `POST` | `/v1/validators/jobs/{id}/claim` | `validators:write` | Claim a validation job for 30 minutes |
| `POST` | `/v1/attestations` | `validators:write` | Verify and record an independently signed report and Monad transaction hash |
| `GET` | `/v1/attestations/{id}` | Public, rate-limited | Read a submitted attestation and its privacy-safe report |
| `GET` | `/v1/channels/stable/manifest` | Public, rate-limited | Read the short-lived signed Stable manifest |
| `GET` | `/v1/defense-versions/{id}/bundle` | Public, rate-limited | Download an immutable content-addressed Defense Module bundle |
| `POST` | `/v1/defense-versions/{id}/quarantine` | `safety:write` | Queue a guardian quarantine with public evidence and an optional replacement |

Usage and approval route families are reserved and return a clear `501` response until their planned phases.

## Storage boundary

Phase 8 uses Postgres for public metadata, defense versions, replay state, durable idempotency leases, and evidence-object references. Encrypted evidence bytes are stored separately in a content-addressed filesystem store with owner-only file modes. The included interfaces keep both components replaceable by managed Postgres and S3-compatible storage later.

The database never contains evidence ciphertext, and the public receipt route never returns the encrypted evidence envelope. Private retrieval checks the authenticated tenant and verifies the stored bytes against the receipt's SHA-256 commitment before parsing them.

Postgres migrations are transactional and idempotent:

```bash
pnpm db:migrate
```

Evidence retention defaults to 30 days and can only be configured downward for the MVP:

```bash
EVIDENCE_RETENTION_DAYS=30 pnpm retention:purge
```

Deleting retained evidence removes its object and clears the private object reference while preserving the public receipt and immutable evidence hash. `pg-mem` is used only for fast compatibility tests; deployed services must use PostgreSQL.

The server health route checks both the database and object-storage root. It returns a sanitized `503` if either dependency is unavailable.

## Monad transaction adapter

Set the Monad RPC, dedicated signer key, deployed contract addresses, ERC-8004 agent ID, and confirmation threshold shown in `.env.example` to enable Phase 10. Configuration is all-or-nothing; partial chain configuration stops startup instead of silently dropping requested commitments.

When `publishCommitment` is true, receipt intake requires the authenticated subject's configured ERC-8004 identity and returns a durable pending operation ID. The background worker persists signed bytes before broadcast, rebroadcasts the same transaction after ambiguous RPC failures, waits for the configured confirmations, and exposes only sanitized public status. Chain writes are serialized for the single MVP signer to prevent nonce collisions across server instances.

## Independent validation

Completed canonical replays create validation jobs when Monad is configured. A validator API identity must map to a distinct ERC-8004 agent ID and wallet address. The claim endpoint binds both values to an expiring job lease.

The validator downloads only the public Defense Module bundle and declared replay profile. Submission requires a new replay report, a wallet signature covering every attestation field, and the validator's Monad transaction hash. The API rejects the canonical control-plane report, mismatched artifact commitments, self-attestation, stale claims, and signatures from another wallet.

## Stable manifest publication

Set `DADIENG_MANIFEST_PRIVATE_KEY`, `DADIENG_PUBLIC_BASE_URL`, and optionally `DADIENG_MANIFEST_TTL_SECONDS` together with the complete Monad configuration. The manifest key is a dedicated off-chain signing key and should not be the transaction signer.

The control plane includes only versions whose current Monad Registry state is Stable and whose on-chain commitments match the stored bundle. It signs a short-lived manifest, links it to the prior manifest hash, persists the append-only lineage, and serves it with an ETag. Bundle URLs are immutable and content-addressed. If Monad verification or signing fails, the endpoint returns a sanitized `503` rather than publishing an unverified set.

Manifest reads recheck currently selected versions even before expiry. After a confirmed quarantine, the next manifest links to the prior hash and selects the highest older version from the same defense family that remains Stable on Monad. Quarantine requests are authenticated, idempotent, and return a pending chain operation; they never imply that the Registry changed before confirmation.
