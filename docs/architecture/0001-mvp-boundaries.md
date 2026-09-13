# Architecture Decision 0001: MVP boundaries

Status: Accepted

## Decision

Dadieng begins with TypeScript agents and an MCP tool-result attack. Security decisions execute locally and deterministically. Private incident content remains offchain. Monad will later hold shared commitments, version state, attestations, quarantines, and revocations.

## Initial trust boundaries

- Agent edge may contain private prompts, credentials, and tool results.
- Public Threat Receipts contain sanitized classifications and content hashes only.
- Defense Modules declare no network access and no clock access.
- Replay reports bind the defense version, artifact, suite, execution image, seed, Monad chain, and registry.
- Model-generated analysis may propose tests but cannot approve a defense.
- Stable promotion will require independent validator attestations.

## Delivery rule

No dashboard, rewards system, or sponsor-specific integration takes priority over the complete attack-to-protection lifecycle.
