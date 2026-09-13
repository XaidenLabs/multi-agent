# Dadieng landing page

The public product site and SDK documentation for Dadieng. The visual system
uses Dadieng's supplied logo, warm black/red identity, protocol architecture,
integrations, and honest package
availability states.

```bash
pnpm --filter @dadieng/landing dev
pnpm --filter @dadieng/landing build
```

The production bundle includes Cloudflare and Vercel adapters. Vercel serves
the unified site at [dadieng.vercel.app](https://dadieng.vercel.app), with
`main` connected for automatic production deployments and Envio supplying the
live Monad read model.
