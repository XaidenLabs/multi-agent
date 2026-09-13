# Architecture Decision 0009: Monad trust contracts

Status: Accepted
Phase: 9

## Decision

Dadieng deploys three immutable contracts that retain the product specification's six logical interfaces:

1. `DadiengRegistry` combines Defense Registry, Threat Receipt Registry, and the publication/promotion/receipt portions of Protocol Config.
2. `DadiengValidation` implements the Validation Registry Adapter.
3. `DadiengRewards` combines Usage Receipt Registry, Reward Distributor, and the usage/claim portions of Protocol Config.

`DadiengRegistry` is deployed first. `DadiengValidation` and `DadiengRewards` hold immutable Registry references. Registry's Validation reference is configured exactly once to close the deployment dependency without introducing a proxy or mutable adapter.

## State and trust boundaries

The enforced defense path is:

```text
Draft -> Candidate -> Stable
  |          |
  +-> Rejected
  +-> Quarantined -> Revoked
             ^
Stable -------+
```

- A candidate requires a complete replay commitment.
- A stable release requires a finalized independent-validator threshold.
- An author address or its agent identity cannot contribute to its own threshold.
- Each registered validator agent identity contributes at most one attestation.
- Quarantine requires a public reason and evidence commitment; revocation is terminal.
- Usage commitments accept only stable version keys.
- Reward allocation requires an unchallenged finalized usage batch and prefunded epoch.
- Claims use checks-effects-interactions plus a reentrancy guard.

Emergency pauses are scoped. Publication, promotion, receipt submission, usage commitments, and claims can be stopped independently. Reads remain available, and a pause can carry an on-chain expiry.

## Data boundary

On-chain state contains content commitments and public lifecycle metadata only. Full bundles, replay suites, SBOMs, raw/encrypted incident evidence, full validator reports, usage leaves, and telemetry remain off-chain. This preserves public auditability without putting customer data or exploit content on Monad.

## Upgrade policy

The Phase 9 contracts are not proxies. Protocol evolution uses new immutable deployments plus explicit adapter/version migration in later phases. Any future upgrade mechanism requires a separate decision record, multisig/timelock controls, storage-layout and diff review, testnet rehearsal, and a rollback plan.
