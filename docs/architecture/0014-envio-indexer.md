# Envio event indexer

## Decision

Dadieng uses Envio HyperIndex v3 to derive its public query model from the Registry, Validation, and Rewards contracts. The checked-in project contains a self-contained contract-event configuration, GraphQL schema, and typed handlers. Contract addresses and the Monad start block come from environment variables so the same source can index local, preview, or testnet deployments.

The indexer stores defense and version state, replay commitments, quarantine evidence and replacements, validators and challenges, receipt links, usage batches, reward accounting, pause state, and aggregate protocol metrics. The console reads this model for discovery and operations while continuing to show transaction links and chain-derived identifiers.

## Consistency

Monad is the source of truth. HyperIndex reorg rollback remains enabled. Entity IDs use immutable protocol keys or transaction hash plus log index, which makes event replay idempotent. Status counters change from the event's old and new values instead of assuming a forward-only lifecycle, so reprocessing and emergency transitions remain coherent.

Every metrics response includes `lastIndexedBlock` and `lastIndexedAt`. Clients compare the derived timestamp to a 15-second MVP freshness target and visibly mark stale analytics. A stale or unavailable indexer never changes Registry state, signs manifests, promotes versions, or authorizes a local agent action.

## Operations

`envio codegen` validates the configuration and generates project-specific handler types. The TypeScript build then checks every handler against those types. Local indexing uses Docker through `envio dev`; hosted operation uses the same committed artifacts. To recover from divergence, operators stop the derived service, verify the configured chain, addresses, and start block, rebuild from a known checkpoint, and compare indexed version states with direct Monad reads before clearing the stale banner.
