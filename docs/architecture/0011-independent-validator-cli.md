# Independent validator CLI

## Decision

Dadieng validators run a separate `dadieng-validator` application. The control plane publishes exact public Defense Module bundles as expiring jobs. It never supplies private incident evidence, validator private keys, or a result that the validator is allowed to sign as its own.

The validator verifies the job's version key, Registry and Validation contract code, candidate status, manifest and artifact commitments, registered ERC-8004 identity, and author independence against Monad. It then interprets the data-only `dadieng-rules` artifact locally with network disabled by the declared replay profile and produces a fresh replay report.

The validator wallet signs a deterministic message containing every attestation field. The same wallet prepares and broadcasts `submitAttestation` directly to Monad through the durable transaction coordinator. The control plane records the independently signed report only after the CLI observes the configured confirmation depth.

## Trust boundary

- The control plane authenticates job access and binds a claim to a registered validator identity.
- The validator treats all downloaded job data as untrusted and verifies schema, content hashes, and on-chain commitments before execution.
- Defense authors cannot validate their own on-chain identity.
- The validator never downloads raw prompts, encrypted incident evidence, credentials, or private tool results.
- The validator private key remains in the validator process environment and is never sent to the API or written to the workspace.
- Prepared signed transaction bytes are stored locally with owner-only permissions so ambiguous RPC failures can reuse identical bytes.
- A submitted API record means the validator observed a confirmed Monad transaction. The contract remains the authority for identity, uniqueness, candidate state, and finalization.

## Failure handling

Hash, identity, signature, author-independence, contract-code, and candidate-state failures are terminal for the current job data. RPC transport failures remain retryable. Job claims expire after 30 minutes and can be reclaimed. Repeating `attest` reuses the same attestation and durable logical operation instead of creating another signature or nonce.
