# Degraded-service and recovery runbook

- Monad RPC degraded: keep local verified rules active, stop promotions and
  reward writes, and show finality as unknown.
- Envio stale: show the stale banner, compare critical state directly with
  Monad, and rebuild from the configured start block before clearing it.
- Replay stuck: allow the lease to expire, verify no worker is still active,
  and requeue the idempotent job. Never accept a partial report.
- Validator threshold missing: keep Candidate status and request another
  independently owned validator. Never count repeated identities twice.
- Qwen unavailable: preserve the canonical suite and defer generated variants;
  model availability never weakens existing protection.
- CRE unavailable: run no automatic lifecycle transition. Existing local SDK
  enforcement continues.
- Suspected bad Stable version: guardian quarantines with public reason and
  evidence commitment; wait for Monad confirmation; verify the new manifest
  selects the highest older compatible Stable version.

Use `pnpm demo:reset` only for `.dadieng/demo`. It does not erase Postgres,
object storage, contracts, keys, or user files.
