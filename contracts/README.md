# Dadieng contracts

Phase 9 implements Dadieng's immutable on-chain trust core as three deployable contracts while preserving the six logical protocol surfaces from the product specification.

## Deployables

- `DadiengRegistry`: defense identity and version lifecycle, replay commitments, sanitized threat-receipt commitments, quarantine/revocation, and scoped publication controls.
- `DadiengValidation`: registered validator identities, self-attestation prevention, one vote per ERC-8004 agent identity, challenges, and threshold finalization.
- `DadiengRewards`: stable-version usage roots, batch challenge/finalization, prefunded epoch allocations, and pull-based native-token claims.

The contracts are deliberately non-upgradeable. Released versions and attestations are immutable. A revoked version remains readable forever and replacement occurs through a new version key.

No prompts, tool results, credentials, raw evidence, replay fixtures, reports, telemetry, or Merkle leaves are stored on-chain. Only identifiers, hashes, sanitized classifications, URIs, counters, roles, and lifecycle state are committed.

## Local verification

```bash
pnpm --filter @dadieng/contracts build
pnpm --filter @dadieng/contracts typecheck
pnpm --filter @dadieng/contracts test
```

The test suite covers authorization, immutable version keys, replay completeness, independent validator thresholds, identity deduplication, self-attestation, challenges, scoped and expiring pauses, quarantine/revocation, stable-only usage, batch finalization, funding, and single-use reward claims.

## Monad testnet deployment

Use a dedicated test key. Never place a funded production key in the repository.

```bash
export MONAD_RPC_URL="https://testnet-rpc.monad.xyz"
export MONAD_PRIVATE_KEY="0x..."
pnpm --filter @dadieng/contracts exec hardhat ignition deploy \
  ignition/modules/DadiengProtocol.ts \
  --network monadTestnet \
  --build-profile production
```

The deployment account initially receives `DEFAULT_ADMIN_ROLE`. After deployment, bootstrap the operational role addresses, test the complete lifecycle on testnet, and transfer administration to the approved multisig before any production use.

## Role separation

- `AUTHOR_ROLE`: register defenses and publish owned immutable versions.
- `VALIDATOR_ROLE`: submit an attestation through a unique registered agent identity.
- `RELEASE_MANAGER_ROLE`: promote validated candidates and finalize usage batches.
- `GUARDIAN_ROLE`: quarantine/revoke versions, challenge attestations/batches, and control scoped emergency pauses. It cannot transfer treasury funds.
- `TREASURY_ROLE`: fund reward epochs. It cannot publish or validate defenses.
- `DEFAULT_ADMIN_ROLE`: configure identities, thresholds, and roles. Production ownership must be a multisig/timelock-controlled address.
