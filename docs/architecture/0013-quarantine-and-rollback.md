# Quarantine and rollback

## Decision

Dadieng guardians quarantine a published version through an authenticated, idempotent control-plane request. The request carries a public-safe reason code, a SHA-256 evidence commitment, and an optional replacement version from the same defense family. The control plane queues the exact `quarantineVersion` Monad transaction and returns a durable operation ID without claiming chain completion.

The Registry remains authoritative. Stable-manifest publication rechecks every active entry against current Monad state even while the cached manifest is unexpired. When a selected version becomes Quarantined, the publisher creates a new signed manifest linked to the prior manifest hash. It selects the highest semantic version in that defense family that still has Stable status and matching commitments.

## Recovery behavior

The SDK accepts the rollback manifest only after its normal signature, network, time, lineage, compatibility, hash, Monad, and shadow-suite checks. Activation replaces the quarantined version with the selected older Stable version as one complete set. The former set remains in the previous-cache slot for audit continuity but cannot reactivate through an online sync because its Monad status is checked again.

If no older Stable version exists, the new manifest omits that defense. Dadieng does not relabel a Candidate version as safe during an emergency. Offline clients follow their configured failure policy and expose last-known-good use as degraded behavior until they can observe current Monad state.

## Safety constraints

- Only an identity with `safety:write` can queue quarantine through the API.
- A replacement must be another published version of the same defense.
- Reason and evidence commitments are public; incident plaintext remains private.
- The API reports Pending until the chain operation confirms.
- A signed manifest cannot keep a quarantined version active after an online Monad recheck.
