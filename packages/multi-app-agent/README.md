# Dadieng multi-app incident coordinator

Turns one privacy-safe Dadieng threat receipt into a resumable response across GitHub, Slack, and Notion.

The ordered workflow opens a GitHub remediation issue, alerts responders in Slack, and records the incident in a Notion database. Every action receives a stable idempotency key, every completed step is checkpointed, concurrent delivery of the same receipt is serialized, and transient `429`/`5xx` failures retry with bounded exponential backoff.

The coordinator rejects summaries containing URLs, credential labels, bearer tokens, or environment-secret references. Pass only Dadieng's sanitized receipt summary and evidence commitment—never raw prompts, tool output, or encrypted evidence. The live runner uses the atomic, owner-only `FileWorkflowStore`; a horizontally scaled deployment should implement `WorkflowStore` with transactional database locking.
