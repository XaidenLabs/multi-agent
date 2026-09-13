# Multi-App AI Agent Hackathon brief

## Product

Dadieng Incident Commander is a security-response agent that takes a blocked AI-agent incident and completes an ordered workflow across three external apps:

1. **GitHub** — opens a remediation issue with severity, sanitized summary, receipt ID, and evidence commitment.
2. **Slack** — alerts the responder channel with a stable client message ID.
3. **Notion** — records the incident in the team's knowledge base for review and learning.

The useful loop is: detect → contain → coordinate → preserve organizational memory. Dadieng supplies the local detection, privacy-safe receipt, deterministic policy decision, and replay evidence; the coordinator turns that trusted result into real team action.

## System boundary

Raw prompts, tool results, credentials, destinations, and encrypted evidence never enter the multi-app workflow. The coordinator accepts only a controlled attack class, severity, 280-character sanitized summary, receipt ID, timestamp, and SHA-256 evidence commitment. It rejects summaries containing URLs, environment-secret references, credential labels, private-key labels, or bearer-token shapes before any app runs.

The action order is intentionally fixed: GitHub → Slack → Notion. Responders receive the durable work item before the alert, and the knowledge-base record is created only after notification succeeds.

## Reliability and evaluation

- Stable workflow ID: `incident:<receiptId>`.
- Stable per-app idempotency key derived from workflow ID and app name.
- Durable `WorkflowStore` interface with per-workflow exclusive execution. The live runner uses atomic, owner-only filesystem checkpoints; a horizontally scaled production deployment must bind locking and checkpoints to Postgres or another transactional store.
- Checkpoint after each attempt and each completed action.
- Resume skips completed actions.
- A receipt ID cannot be reused with changed incident data.
- Only HTTP `429` and `5xx` app failures retry; authentication, validation, and other permanent failures stop immediately.
- Bounded exponential backoff and three attempts by default.
- Public errors are sanitized and capped; remote response bodies are not persisted.
- Workflow completion requires all three app results.

Automated evaluation covers ordering, unique idempotency keys, concurrent-delivery serialization, no-duplicate resume, exhausted-run recovery, transient retry, fail-closed privacy validation, live-client request shape, and the complete Dadieng-to-three-app demo. The credential-free demo deliberately injects a Slack `503`, recovers on the second attempt, and reruns the completed workflow to prove that only three actions were recorded.

## Two-minute demo script

Record at 1920×1080 with the browser zoomed so the important card fills the
frame. Hide bookmarks, notifications, tokens, terminal history, and personal
Notion pages. Use the already-created incident; do not regenerate credentials
while recording.

**0:00–0:13 — Landing page hero and two-agent loop.** Start at the production
homepage, hold the hero for five seconds, then scroll to “The technical proof.”
Voice-over: “AI agents now read untrusted content and act through real systems.
Dadieng is the verification and distribution protocol for their defenses. When
Agent A meets an unknown attack, it blocks locally, commits privacy-safe
evidence, and produces a defense Agent B can independently verify and inherit.”

**0:13–0:38 — Attack and containment.** Open `/commander`. Frame the malicious
support ticket and the `BLOCK` decision, then click **Run support-agent
scenario**. Voice-over: “This support ticket hides an instruction to read
deployment credentials and send them outside the company. Dadieng stops the
tool path before execution. Only a sanitized receipt crosses the boundary; the
raw ticket, destination, and credentials never reach another app.”

**0:38–0:58 — Failure-aware orchestration.** Keep the completed workflow card
on screen. Voice-over: “The incident commander now performs one ordered task
across GitHub, Slack, and Notion. The rehearsal injects a Slack 503, retries
with the same idempotency key, checkpoints every step, and resumes without
duplicating completed work. Here Slack succeeds on attempt two and exposure
remains zero.”

**0:58–1:27 — Real external apps.** Show GitHub issue #2, the Slack alert, and
the Notion record for `support-ticket-4821-live-20260913-verified`, about ten
seconds each. Voice-over: “These are the real outputs from the live runner: a
labelled GitHub remediation issue, a responder alert in Slack, and a structured
Notion incident record. An immediate rerun returned these same three external
IDs, proving duplicate-free delivery against the actual apps.”

**1:27–1:48 — Technical evidence.** Open `/proof`; frame the 32 attack cases,
28 clean controls, 100 deterministic runs, and Monad contracts. Voice-over:
“A detection is not automatically trusted. Dadieng normalizes encoded,
Unicode, split-field, nested, and multilingual attacks, preserves clean
controls, reproduces the suite one hundred times, then requires independent
validation before Monad marks a signed version Stable.”

**1:48–2:00 — Close.** Return to the landing-page inheritance loop or slide 7.
Voice-over: “Threat feeds share what happened. Dadieng proves which defense
works, preserves utility, and can be rolled back. One agent learns. Every agent
hardens.”

## Live rehearsal checklist

- Create a dedicated GitHub test repository and fine-grained token with Issues write access.
- Install a Slack bot in a dedicated test workspace/channel with `chat:write`.
- Create a Notion integration, share a test data source with it, and add `Name`, `Severity`, `Receipt`, and `Summary` properties matching the client payload.
- Put credentials only in the local environment; never commit `.env`.
- Run the credential-free test suite first, then `pnpm --filter @dadieng/multi-app-agent-demo live` with a sanitized receipt ID and evidence hash.
- Screen-record one successful workflow, one injected transient failure, and a repeat run showing no duplicates.

The live external-app run was verified on 13 September 2026. Public proof is
the GitHub issue; Slack and Notion links require access to their private test
workspaces. The credential-free Commander remains labelled as a rehearsal and
must not be described as the live app execution itself.
