# npm distribution

Dadieng's browser/server code and its npm packages are different products.

## What goes to npm

The public `0.1.0` release was published in this dependency order:

1. `@dadieng/schemas`
2. `@dadieng/defense-module`, `@dadieng/policy-engine`,
   `@dadieng/receipt-sanitizer`, and `@dadieng/contracts-client`
3. `@dadieng/sdk`
4. `@dadieng/adapters`

pnpm rewrites `workspace:*` ranges to the matching release version when it
packs a workspace package. The control plane, replay worker, validator CLI,
indexer, Operations view, landing page, and CRE workflow are deployed services or
operational artifacts; they are not installed into adopter applications.

## Current release

The seven packages above are public under the npm `@dadieng` organization at
version `0.1.0`. They are currently marked `UNLICENSED`: public registry access
does not grant an open-source license. All other workspace applications and
operational packages remain private.

The release passed the full test and type-check suites, tarball inspection, a
high-severity production dependency audit, registry integrity verification,
and a clean external installation smoke test. Future releases should move to
npm trusted publishing from a protected GitHub release environment after the
repository visibility and licensing policy are approved.

## Hosting map

- npm: compiled adopter SDK and adapters
- web hosting: unified product site, documentation, Proof, and `/docs#operations`
- application compute: control plane, replay workers, and validator workers
- Monad: canonical protocol contracts and lifecycle state
- Envio: derived GraphQL read model
- Chainlink CRE: deployed orchestration workflow
- private object storage: encrypted evidence and immutable artifacts
