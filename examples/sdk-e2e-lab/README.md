# Dadieng SDK end-to-end failure lab

This mini project runs the real Dadieng SDK and multi-app coordinator against deterministic GitHub, Slack, and Notion test doubles.

```bash
pnpm sdk:e2e
```

The lab verifies malicious MCP containment, a retryable Slack outage, a permanent Notion rejection, recovery after the permission issue is fixed, restart-safe checkpoints, duplicate delivery, and fail-closed privacy validation. It exits non-zero when any check fails.
