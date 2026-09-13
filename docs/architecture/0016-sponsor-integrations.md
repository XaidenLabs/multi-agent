# Sponsor integrations

## Decision

Sponsor systems sit at explicit protocol boundaries. Dadieng remains useful
without any one vendor, and no sponsor receives raw prompts, credentials, or
authority to make a release decision.

- Chainlink CRE schedules and coordinates an idempotent validation-cycle
  callback. Its workflow uses CRE secrets, node-mode HTTP consensus, and a
  bounded sanitized response. Replay workers remain the sandbox.
- Dynamic supplies the authenticated participant wallet. Dadieng asks that
  wallet to sign a short-lived, chain-bound, nonce-bound protocol intent and
  verifies that the signature recovers to the participant address.
- Mera-compatible WebAuthn PRF output derives non-exportable, namespaced AES-GCM
  keys through HKDF. A fresh profile with the same passkey can decrypt the same
  envelope; the PRF output and encryption key are never persisted.
- Envio projects Monad events into the read model built in Phase 14.
- Qwen receives only controlled taxonomy and a sanitized summary. Its one
  read-only tool exposes the same sanitized taxonomy. Generated variants are
  schema-checked and bounded; deterministic replay assertions decide release.

## Failure boundaries

CRE callback writes are authenticated, scoped, rate-limited, and idempotent.
Qwen calls have a fixed timeout and cannot request arbitrary tools. Mera rejects
unsupported authenticators and weak PRF outputs. Dynamic signatures bind exact
intent and expiration. Envio failure degrades analytics only. Missing sponsor
credentials keep the relevant live proof unavailable without weakening local
enforcement.

## Live proof

The repository contains buildable SDK integrations and an official Chainlink
CRE TypeScript workflow. A sponsor deployment, Dynamic environment, Qwen API
call, and physical cross-device passkey ceremony require owner-provided sponsor
accounts and must be captured as submission evidence; they are not fabricated
by local tests.
