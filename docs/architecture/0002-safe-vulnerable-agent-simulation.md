# Architecture Decision 0002: Safe vulnerable-agent simulation

Status: Accepted

## Context

Dadieng needs a reproducible baseline failure without placing real credentials, networks, or user data at risk during development and judging.

## Decision

The Phase 2 vulnerable agent records dangerous capability requests as accepted by its simulated planner, but never executes them. Every capability record carries `simulated: true` and `executed: false`.

The protected agent consumes the identical fixture and records the same requests with a blocked disposition. The comparison is valid only when both traces contain the same fixture ID and SHA-256 fingerprint.

## Consequences

- The demo proves behavioral vulnerability without exfiltrating data.
- Test output is deterministic and safe for CI.
- Later integration tests may execute harmless sandbox targets, but production credentials remain forbidden.
- Public traces describe capability classes and outcomes without copying the hostile MCP content.
