# Stable manifest synchronization

## Decision

Dadieng publishes the `stable` channel as a short-lived, EIP-191-signed manifest. The control plane derives each entry from an immutable stored Defense Module and accepts it only when the Monad Registry reports the exact version as Stable with matching manifest and artifact commitments.

Every manifest includes its network, Registry address, generation and expiry times, and the hash of the preceding manifest. The control plane stores this append-only lineage in Postgres and prevents two manifests from claiming the same parent, including the genesis parent. Manifest responses are revalidatable with an ETag; content-addressed bundle responses are immutable.

The SDK treats the network response and local cache as untrusted. Before activation it verifies the manifest schema and signer, network binding, clock window, lineage, module hashes, SDK/event/adapter compatibility, deployed Registry code, current Monad lifecycle state and commitments, and the complete embedded defense suite. Only the resulting data-only rules reach the local policy engine.

## Activation and recovery

Synchronization is serialized within a client. A complete verified set replaces the active engine in one callback; partially verified sets never activate. The durable cache keeps the current and immediately previous verified sets, writes through an atomic rename, and uses owner-only directory and file modes.

An unavailable or invalid refresh follows an explicit policy:

- `last-known-good` activates the most recently verified cached set, even after its publication window expires.
- `closed` rejects synchronization when no verified refresh can be activated.
- `open` leaves the existing engine untouched and reports that refresh failed.

An unchanged signed manifest is not enough by itself: the SDK rechecks every cached version against current Monad state before reactivation. Quarantine-driven manifest replacement and rollback orchestration remain Phase 13 responsibilities.

## Trust boundary

- The manifest signing key is separate from the Monad transaction signer.
- A manifest signature cannot override Registry lifecycle state or commitments.
- Monad state cannot substitute different off-chain bytes because every bundle component is content-addressed.
- Cache contents cannot bypass schema, manifest hash, bundle hash, identity, or Monad checks.
- Network failures never produce a partially activated defense set.
