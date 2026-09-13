# Dadieng Envio indexer

This HyperIndex v3 project derives the public Dadieng security graph from events emitted by the Registry, Validation, and Rewards contracts on Monad. Monad remains canonical; this index is a query and analytics layer.

## Configure

Set the deployed addresses and optional start block:

```bash
export ENVIO_MONAD_RPC_URL="https://testnet-rpc.monad.xyz"
export ENVIO_CHAIN_ID=10143
export ENVIO_START_BLOCK=0
export ENVIO_DADIENG_REGISTRY_ADDRESS="0x..."
export ENVIO_DADIENG_VALIDATION_ADDRESS="0x..."
export ENVIO_DADIENG_REWARDS_ADDRESS="0x..."
```

The checked-in fallback addresses exist only so code generation works before deployment. Never treat data from those placeholders as a live Dadieng deployment.

## Generate and run

```bash
pnpm --filter @dadieng/indexer codegen
pnpm --filter @dadieng/indexer build
pnpm --filter @dadieng/indexer dev
```

Local `dev` requires Docker. Envio Cloud can run the same `config.yaml`, `schema.graphql`, and handlers without changing the data model. Set the Cloud root directory to `indexer`, the config path to `config.yaml`, and provide the `ENVIO_`-prefixed values above in its environment settings.

## Indexed views

The GraphQL schema exposes defense families and lifecycle versions, replay commitments, safety actions and replacements, validator identities and challenge history, sanitized receipt links, usage batches, reward claims, pause state, and aggregate protocol metrics. Every operational client must compare `lastIndexedAt` with its freshness threshold and label stale data. Rebuilds are safe because HyperIndex reorg rollback is enabled and event-derived IDs are deterministic.
