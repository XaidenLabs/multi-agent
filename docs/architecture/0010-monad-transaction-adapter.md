# Architecture Decision 0010 Monad Transaction Adapter

Status: Accepted

## Decision

Dadieng uses an asynchronous, durable transaction outbox between control-plane writes and Monad. API requests return a stable operation ID with pending state; a worker then prepares, broadcasts, and confirms the transaction in separate leased turns.

The signed serialized transaction is stored before broadcast. This is the key recovery boundary: an ambiguous RPC timeout triggers rebroadcast of the same bytes and transaction hash, never creation of a second logical write.

## Operation lifecycle

- `queued`: validated public operation data is durably recorded.
- `prepared`: simulation passed and the signed transaction bytes plus expected hash are durable.
- `submitted`: the exact prepared transaction was accepted or was already known by the RPC node.
- `confirmed`: a successful receipt reached the configured confirmation threshold.
- `failed`: simulation, signing, or execution reached a sanitized terminal failure.

RPC and transport failures are retryable. Contract simulation failures, malformed operation data, hash mismatches, and reverted receipts are terminal. Transaction replacements can update the tracked public hash without changing the logical operation ID.

## Concurrency and recovery

The Phase 10 signer queue is serialized. Postgres enforces at most one active signer lease, and lease expiry permits recovery after worker failure. This avoids concurrent nonce allocation across processes. Horizontal signer sharding can be introduced later with one independent lease slot per signer.

The database stores operation payloads, signed transaction bytes, public transaction hashes, attempts, confirmation state, and sanitized error codes. API responses omit signed bytes, claim tokens, RPC messages, and internal exception details.

## Identity and privacy

Receipt publication requires an ERC-8004 identity explicitly bound to the authenticated API subject. Only the sanitized receipt hash, encrypted-evidence commitment, classification identifier, and public agent identity are encoded. Raw incident content and encrypted evidence bytes never enter calldata or public operation responses.

## Finality

A broadcast transaction is not reported as complete. The adapter reads the receipt and current block height and marks the operation confirmed only after the configured confirmation count. A missing receipt remains pending, allowing reorgs or temporary RPC inconsistency to settle without a false completion signal.
