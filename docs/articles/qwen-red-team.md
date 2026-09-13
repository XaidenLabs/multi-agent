# Qwen proposes the attack. Dadieng decides the release.

AI-agent defenses fail when their tests stop evolving. Dadieng uses Qwen as an
authorized red-team planner: a sanitized threat receipt provides an attack
class, affected capability classes, and a short non-sensitive summary. Qwen can
inspect that controlled taxonomy through one bounded tool and propose synthetic
replay variants.

That model is intentionally not the judge. Every proposal becomes a structured
fixture with an expected safe outcome. Dadieng's replay worker executes the
canonical attacks and legitimate controls in an isolated, deterministic
environment. Independent validators reproduce the report before Monad records
the lifecycle transition. A fluent model answer cannot override a failed
assertion, missing validator threshold, or mismatched commitment.

This separation gives the model room to explore while keeping authority in
verifiable code. It also protects incident privacy: Qwen never needs the raw
prompt, private evidence bundle, credentials, or tenant data. The public output
is a set of bounded test ideas; the durable result is a signed report hash.

The useful pattern is broader than security testing: let a model expand the
search space, make tools narrow and observable, and reserve consequential
decisions for deterministic assertions and independently verifiable state.
