# Dadieng Chainlink CRE validation workflow

This workflow is the decentralized coordinator for a Dadieng validation cycle.
It wakes on a schedule and asks the control plane to perform one idempotent
cycle: claim candidate work, request Qwen variants, dispatch deterministic
replays, collect independent attestations, and return only sanitized hashes and
status. CRE coordinates; it is not the replay sandbox and receives no raw
evidence.

After installing the CRE CLI and setting a real preview URL:

```bash
cre workflow simulate --target staging-settings --config config.staging.json main.ts
```

Deployment and broadcast require sponsor credentials and funded testnet signing
material. They are intentionally never committed.
