# Architecture Decision 0003: Local SDK enforcement

Status: Accepted

## Decision

Dadieng evaluates agent events locally through six public lifecycle hooks. Model and tool content is normalized and fingerprinted before deterministic Defense Modules run. Blockchain access, remote APIs, telemetry sinks, and incident listeners are not part of the synchronous decision dependency chain.

## Public hooks

- `beforeModel()`
- `afterModel()`
- `beforeToolCall()`
- `afterToolResult()`
- `onDecision()`
- `onIncident()`

## Failure behavior

SDK adopters select one of three policies:

- `open` allows an action when evaluation fails.
- `closed` blocks an action when evaluation fails.
- `last-known-good` blocks high and critical capabilities while observing low and medium capabilities. Phase 12 will connect this behavior to a verified manifest cache.

Listener failures are recorded as diagnostics and cannot change an enforcement result. Content that cannot be normalized is treated as an evaluation failure rather than harmless content.

## Privacy boundary

Normalized event content remains within the adopter process. Public Threat Receipts contain classifications and hashes, not the underlying prompt, tool result, arguments, credentials, or destination.
