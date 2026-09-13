# Dadieng contracts client

This package is the Phase 10 boundary between Dadieng's control plane and the immutable Monad contracts.

It provides typed calldata for Registry, Validation, and Rewards writes plus a durable operation coordinator. The coordinator does not wait inside an HTTP request. It records an operation ID immediately and advances the operation through these states:

```text
queued -> prepared -> submitted -> confirmed
   |          |            |
   +----------+------------+-> failed
```

Preparation simulates the call, resolves gas and nonce, signs the transaction, and computes its hash. The signed bytes and hash are persisted before broadcast. If broadcasting times out after the node accepted the transaction, the worker rebroadcasts the identical signed bytes instead of preparing a second transaction.

Only one operation is leased for the configured signer at a time. This prevents concurrent workers from preparing colliding nonces. Leases expire after a worker crash, and another worker can safely continue from the last durable state.

The public operation view exposes stage, transaction hash, confirmation count, sanitized error code, and safe-retry state. It never exposes the serialized signed transaction or internal RPC errors.

## Configuration

The production control plane enables the adapter only when all Monad variables are present:

```text
MONAD_RPC_URL
MONAD_PRIVATE_KEY
DADIENG_REGISTRY_ADDRESS
DADIENG_VALIDATION_ADDRESS
DADIENG_REWARDS_ADDRESS
DADIENG_ERC8004_AGENT_ID
DADIENG_CHAIN_CONFIRMATIONS
```

Use a dedicated role-limited signer and secret injection in deployed environments. Do not commit or log a private key.
