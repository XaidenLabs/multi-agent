# Full protocol demonstration

Runs the complete credential-free proof with synthetic evidence and no network
or filesystem access in replay. It executes the same canonical replay 100
times, requires two independent validator identities, projects the Stable event
into Envio-style metrics, and proves a second agent blocks the attack while a
legitimate control remains allowed.

```bash
pnpm --filter @dadieng/full-protocol-demo demo
```

The output says `credential-free-local` deliberately. Replace the synthetic
Qwen, validator, and Monad operations only in the live testnet runbook after
sponsor credentials and deployed addresses are configured.
