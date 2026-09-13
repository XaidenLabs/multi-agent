![Dadieng — verified defenses for AI agents](./assets/brand/dadieng-banner.png)

# Dadieng

Dadieng is an open verification and distribution protocol for portable AI-agent defenses. It turns one agent incident into a privacy-safe, reproducible defense that independent validators can verify before every compatible agent inherits it.

> Threat intelligence tells agents what happened. Dadieng proves which defense works, preserves legitimate behavior, and can be safely distributed.

- **Live product:** [https://dadiengprotocol.luminous-hovercraft.workers.dev/](https://dadiengprotocol.luminous-hovercraft.workers.dev/)
- **Proof page:** [https://dadiengprotocol.luminous-hovercraft.workers.dev/proof](https://dadiengprotocol.luminous-hovercraft.workers.dev/proof)
- **Doc page:** [https://dadiengprotocol.luminous-hovercraft.workers.dev/proof](https://dadiengprotocol.luminous-hovercraft.workers.dev/doc)
- **Example application:** [https://dadiengprotocol.luminous-hovercraft.workers.dev/commander](https://dadiengprotocol.luminous-hovercraft.workers.dev/commander)
- **Video overview:** [https://youtu.be/SBg-5sQ2-9k](https://youtu.be/SBg-5sQ2-9k)
- **Monad Testnet:** chain ID `10143`

## The problem

AI agents ingest untrusted documents, messages, APIs, MCP tool results, and model output, then act through privileged tools. A malicious result can instruct the model to ignore policy, retrieve credentials, or transmit data. A one-off block protects only one execution. A centralized signature feed asks every agent to trust the publisher and can distribute a broken defense that blocks legitimate work.

Dadieng separates the security problem into independently testable stages:

```text
Detection → Evidence → Reproduction → Validation → Distribution
```

The latency-sensitive decision stays local. Monad is never queried before each model or tool call. The network records the canonical lifecycle of a defense after deterministic replay and independent validation.

## The complete protocol loop

```text
Agent A receives an unknown malicious tool result
  ↓
Dadieng SDK blocks the unsafe path locally
  ↓
Receipt sanitizer publishes metadata + SHA-256 commitment, never raw evidence
  ↓
Qwen red-team planning proposes bounded synthetic variants
  ↓
Deterministic replay runs attack cases and clean controls in an isolated environment
  ↓
Independent validators reproduce the report
  ↓
Chainlink CRE coordinates threshold validation
  ↓
Monad finalizes Draft → Candidate → Stable lifecycle state
  ↓
Envio indexes a derived, non-authoritative read model
  ↓
Agent B verifies the signed Stable manifest and swaps defenses atomically
  ↓
The same attack is BLOCKED; a legitimate request remains ALLOWED
```

An incident does not automatically become network policy. Distribution requires a content-addressed bundle, passing attack tests, passing clean controls, reproducible commitments, validator quorum, canonical lifecycle state, and a signed manifest.

## What the SDK does, step by step

`@dadieng/sdk` is the local enforcement runtime. Create one client for each agent process and call it at model and tool boundaries.

```bash
npm install @dadieng/sdk @dadieng/adapters
```

```ts
import { createDadieng } from '@dadieng/sdk'
import { protectMcpClient } from '@dadieng/adapters'

const dadieng = createDadieng({
  agentId: 'support-agent',
  framework: 'mcp',
  mode: 'enforce',
})

const protectedClient = protectMcpClient(rawMcpClient, dadieng)
```

The lifecycle boundaries are:

| Boundary | When it runs | Possible result |
| --- | --- | --- |
| `beforeModel(input)` | Before untrusted context reaches the model | allow, sanitize, or block |
| `afterModel(output)` | Before model output reaches an app or person | allow, sanitize, or block |
| `beforeToolCall(name, args)` | Before a tool can cause a side effect | allow, require approval, or block |
| `afterToolResult(name, result)` | Before untrusted tool output returns to the model | allow, sanitize, or block |

For each event the SDK:

1. Validates the event against the versioned `DadiengEvent` schema.
2. Applies the currently verified local defense bundle.
3. Returns a deterministic `ALLOW`, `OBSERVE`, `REQUIRE_APPROVAL`, or `BLOCK` decision.
4. Prevents the caller from executing a blocked capability.
5. Creates a sanitized `ThreatReceipt` when an incident occurs.
6. Encrypts private evidence under an operator-controlled key.
7. Emits listeners for storage, incident response, or later validation.
8. Continues offline with the last-known-good verified bundle when the network or indexer is unavailable.

The MCP adapter enforces both directions: before a tool request leaves the process and before a tool result returns to the model. The Vercel AI adapter exposes the same boundaries for `generateText`/tool execution flows.

## Privacy boundary

Public receipts contain controlled fields such as receipt ID, agent pseudonym, attack class, defense version, reason codes, timestamp, and evidence commitment.

They do **not** contain raw prompts, raw tool results, credentials, destinations, customer content, personal data, or private encryption material. Tests assert that hostile fixture content and synthetic secrets are absent from serialized receipts and replay reports.

## Portable defense bundles

A bundle contains:

- `manifest.json` — identity, semantic version, compatibility, permissions, and content hashes.
- `artifact.json` — deterministic rules loaded by the local runtime.
- `suite.json` — attack cases and clean controls.
- `sbom.json` — package inventory.

The loader verifies every content hash, defense ID, runtime, entry point, declared outcome, schema compatibility, and permission before execution. Replay rejects modules that request network or filesystem access outside the declared sandbox.

The reference MCP boundary suite currently contains 32 attacks and 28 clean controls. It includes direct, Unicode-obfuscated, punctuation-split, HTML-split, percent-encoded, Base64-encoded, nested JSON, split-field, multilingual, indirect-command, and role-masquerading cases. Those numbers are **local reference-suite evidence**, not live production traffic.

## Replay, validation, and distribution

The replay engine records the defense, suite, image digest, dependency lock hash, runtime, seed, clock, filesystem mode, and network mode. Identical inputs must produce the same report hash. Release eligibility fails when attack effectiveness, control utility, latency, environment policy, case identity, or artifact integrity regresses.

The credential-free full-protocol demo runs 100 byte-identical executions, reproduces validator quorum, simulates Monad lifecycle finalization, derives Envio state, and proves that Agent B blocks the attack while allowing a clean request.

```bash
pnpm demo:final
```

The demo is deliberately labelled `credential-free-local`. It is architecture and reliability evidence, not proof of an external Chainlink, Envio, Qwen, Dynamic, or Mera deployment.

## Monad trust layer

Deployed Monad Testnet contracts:

| Contract | Address |
| --- | --- |
| `DadiengRegistry` | `0x449a547105a5b006277fafd7ec1425c1c7428be5` |
| `DadiengValidation` | `0x022b489deb764a438a57bb70d1363cb884c516bf` |
| `DadiengRewards` | `0xb573d400a3476e05fcb5b518665f142605613305` |

Roles are separated across author, validator, release manager, guardian, treasury, and administrator responsibilities. The initial deployer retains privileged administration until it is transferred to a multisig/timelock; the current deployment is not described as fully permissionless governance.

Envio is a query-optimized derived read model. It does not authorize transitions. Agents verify signatures, hashes, compatibility, expiry, lineage, and Monad lifecycle state before accepting a Stable manifest.

## Quarantine and rollback

If new evidence invalidates a Stable defense, a guardian can quarantine the version. The publisher stops distributing it, selects the highest compatible previous Stable version, signs rollback lineage, and clients verify and swap atomically while retaining last-known-good state.

## Example application: Incident Commander

Incident Commander demonstrates a useful ordered workflow after Dadieng blocks a malicious customer-support ticket:

1. **GitHub** creates a remediation issue labelled `security` and `dadieng`.
2. **Slack** alerts the private response channel.
3. **Notion** writes a durable incident record.

Only the sanitized incident crosses app boundaries. The coordinator uses `incident:<receiptId>` as its workflow identity, derives a stable idempotency key for each app, checkpoints after every attempt, retries only `429` and `5xx` failures, resumes without duplicating completed writes, and rejects reuse of a receipt ID with changed data.

```bash
pnpm demo:multi-app
```

The public Commander is a deterministic credential-free rehearsal and says so. The real runner is:

```bash
pnpm --filter @dadieng/multi-app-agent-demo live
```

Required secrets are listed in `.env.example`. Never paste them into issues, chat, screenshots, recordings, or Git history.
`DADIENG_DEMO_OCCURRED_AT` is also required and must stay unchanged when the
same receipt is retried. The timestamp is part of the incident commitment, so
changing it while reusing a receipt fails closed as conflicting input.

## Run locally

Prerequisites: Node.js 22+, pnpm 11+, and Docker/Postgres only when running the control plane.

```bash
pnpm install
pnpm test
pnpm typecheck
pnpm --filter @dadieng/landing test
pnpm demo
pnpm replay:demo
pnpm demo:final
pnpm demo:multi-app
pnpm sdk:e2e
```

Control plane:

```bash
export DADIENG_API_KEY="replace-with-a-long-random-key"
export DATABASE_URL="postgresql://dadieng:replace-me@127.0.0.1:5432/dadieng"
export DADIENG_OBJECT_ROOT="./.dadieng/objects"
pnpm db:migrate
pnpm api:start
```

## Failure behavior

- Invalid or expired defense bundle: reject it and retain last known good.
- Indexer unavailable: local protection continues; analytics are labelled stale/demo.
- Monad RPC unavailable: no new finalization; already verified local enforcement continues.
- External app `429` or `5xx`: bounded exponential retry with the same idempotency identity.
- Authentication/validation failure: stop immediately; do not retry a permanent error.
- Crash after a completed app write: resume from the durable checkpoint without repeating prior steps.
- Changed incident under the same receipt ID: fail closed.
- Raw evidence in a multi-app summary: reject before the first external action.

Recovery procedures live in `docs/runbooks/`.

## Repository map

- `packages/schemas`: versioned event, decision, defense, receipt, and replay contracts.
- `packages/sdk`: lifecycle interception, Stable-manifest sync, last-known-good caching, and enforcement.
- `packages/adapters`: MCP and Vercel AI SDK protection wrappers.
- `packages/policy-engine`: deterministic local defense evaluation.
- `packages/receipt-sanitizer`: privacy-safe receipts and encrypted evidence.
- `packages/defense-module`: content-addressed bundles, verification, loading, and suites.
- `packages/replay-engine`: deterministic attack/control execution and report verification.
- `packages/contracts-client`: Monad calldata, durable transaction coordination, nonce handling, retry, and confirmation.
- `packages/multi-app-agent`: GitHub, Slack, and Notion clients plus resumable orchestration.
- `packages/sponsor-integrations`: bounded Chainlink CRE, Qwen, Dynamic, and Mera interfaces.
- `apps/control-plane`: authenticated API, Postgres metadata, object storage, retention, and manifest publication.
- `apps/validator-cli`: independent claiming, replay, signing, and validator submission.
- `apps/landing`: public product, documentation, Operations view, Proof page, and Commander example.
- `contracts`: registry, validation, rewards, deployment metadata, and tests.
- `indexer`: Envio schema, handlers, configuration, and freshness model.
- `defenses/mcp-boundary`: committed reference bundle.
- `replays/mcp-boundary`: committed deterministic replay report.
- `examples/full-protocol-demo`: eight-stage two-agent inheritance proof.
- `examples/multi-app-agent`: real and credential-free three-app workflows.
- `examples/sdk-e2e-lab`: failure-injection mini-project.

## Evidence labels

Dadieng uses these words precisely:

- **Deployed** — an independently accessible external resource exists.
- **Live** — a current remote check succeeded.
- **Connection verified** — a scoped remote API operation succeeded.
- **Configured** — required credentials are present; connectivity is not implied.
- **Local reference** — deterministic code and tests run locally.
- **Demo available** — a safe simulation exists.
- **Pending** — external evidence has not been captured.

Synthetic metrics are always marked `DEMO`, `LOCAL TEST`, `REFERENCE SUITE`, or `SIMULATED`. Environment-variable presence is never described as a verified connection.

## Security and responsible use

Dadieng's reference rules are one layer, not a complete semantic security solution. Real deployments should combine canonicalization, structured trust boundaries, capability policy, human approval for high-impact actions, model-assisted semantic analysis, rate limits, sandboxing, audit logs, and continuous adversarial evaluation.

The vulnerable demo never reads or transmits a real secret. It proves that an unsafe planner would propose privileged capabilities; the protected path blocks them before execution.

See `SECURITY.md` for disclosure and supported-version guidance.

## License and submission status

The repository currently declares `UNLICENSED`; do not assume permission to redistribute it until an approved license is added. `docs/SUBMISSION_CHECKLIST.md` is the source of truth for external hackathon evidence. Unchecked items must be described as pending.
