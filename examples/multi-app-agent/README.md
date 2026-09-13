# Multi-app AI agent demo

Run the credential-free proof:

```bash
pnpm demo:multi-app
```

It blocks a synthetic tool-poisoning attempt, creates a privacy-safe receipt, coordinates GitHub → Slack → Notion, injects and recovers from one transient Slack failure, and proves that rerunning the completed workflow creates no duplicate actions.

For a live rehearsal, configure the GitHub, Slack, Notion, and demo receipt variables in `.env.example`, then run `pnpm --filter @dadieng/multi-app-agent-demo live`. Use a dedicated test repository, channel, and Notion database.
