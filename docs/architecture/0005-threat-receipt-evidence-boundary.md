# Architecture Decision 0005: Threat Receipt and private evidence boundary

Status: Accepted

## Decision

Every security-relevant `BLOCK` or `OBSERVE` decision produces two linked artifacts:

- a public `dadieng.receipt.v2` containing controlled taxonomy, sanitized context, fingerprints, a deduplication key, and an evidence commitment;
- a private `dadieng.encrypted-evidence.v1` envelope containing the exact normalized event and policy decision encrypted with AES-256-GCM.

The SHA-256 hash in the public receipt commits to the complete encrypted envelope. The receipt cannot prove that the underlying event is truthful; replay and independent validation provide that evidence in later phases.

## Privacy boundary

Public summaries are assembled exclusively from controlled attack and capability taxonomy values. Raw prompts, tool results, source identities, credentials, personal data, ciphertext, IVs, and authentication tags are excluded. Reporter agent IDs are fingerprinted by default and are included directly only when the SDK adopter explicitly enables attribution.

High and critical receipts are marked as requiring manual review before public disclosure. The schema rejects such receipts if that flag is absent.

## Evidence handling

Encryption keys never enter the receipt or encrypted envelope. The SDK accepts adopter-managed key material and otherwise creates an ephemeral in-memory key for development. The pipeline returns the encrypted envelope to the adopter; Phase 8 will add authorized persistence adapters, while the planned Mera integration may later supply recoverable namespaced keys.

Receipt creation is downstream of the local policy decision. Encryption or sanitization failure is recorded as an SDK diagnostic and suppresses publication, but it cannot turn a block into an allow or invoke incident listeners with a partial artifact.

AES-GCM authenticates the ciphertext and receipt/key context. Any ciphertext, tag, IV, or associated-data mismatch prevents decryption. Bundle-hash verification additionally detects replacement before decrypting.

## Deduplication

The deduplication key commits to taxonomy version, attack class, controlled capability classes, source fingerprint, and sorted reason codes. It excludes receipt IDs, encryption keys, IVs, and ciphertext so equivalent incident reports converge without exposing their contents.
