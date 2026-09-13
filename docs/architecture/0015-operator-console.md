# Operations inside documentation

## Decision

Dadieng ships one responsive read-only Operations surface at `/docs#operations`
inside `apps/landing`. The legacy `/console` URL redirects there for backward
compatibility. Product, documentation, and operations therefore share one
domain and one visual system. The information hierarchy follows the protocol:
health, defenses, receipts, replay results, validators, integrations, rewards,
and safety settings. Every security-sensitive state is written in plain
language and is not encoded by color alone.

## Read model and authority

The site's Worker reads aggregate protocol state from the Envio GraphQL
endpoint through a same-origin `/api/console` route with a bounded timeout.
Missing configuration, network failures, and old indexed timestamps render
explicit demonstration, offline, or stale states. These states never enable a
write or hide the fact that Monad remains the canonical authority.

## Safety and privacy

The Operations view shows pending finality, validator threshold, quarantined versions,
rollback readiness, human-approval boundaries, and evidence privacy. It never
renders raw prompts, secrets, complete private evidence, or signing material.
The supplied Dadieng logo and banner are the canonical visual assets.

## Operations

The Vite build emits static assets plus a Cloudflare-compatible Worker. Content
and Worker tests verify the unified route, Operations information architecture,
honest fallback labeling, and read-only method boundary.
