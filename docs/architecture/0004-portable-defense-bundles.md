# Architecture Decision 0004: Portable Defense Module bundles

Status: Accepted

## Decision

A Dadieng Defense Module is a four-file, content-addressed bundle: a manifest, declarative artifact, test suite, and SBOM. The manifest commits to the other three files with canonical SHA-256 hashes. The loader validates all schemas, hashes, identities, declared outcomes, runtime, and entrypoint before producing an executable defense.

## Local runtime boundary

Phase 4 executes only the constrained `dadieng-rules` format. Rules may match case-insensitive string indicators against an event stage and trust zone, then return a declared policy outcome and reason codes. They cannot perform I/O or access network, filesystem, or clock capabilities.

Although the manifest schema reserves `typescript` and `wasm` runtime identifiers, the local loader rejects them. Supporting executable artifacts requires a later isolated, resource-limited sandbox and must not silently inherit the SDK host process permissions.

## Reproducibility

Object keys are sorted lexicographically before serialization. The artifact, suite, SBOM, and manifest therefore receive stable hashes for identical logical content. Every bundle includes executable attack and control cases so its promised behavior can be checked before activation.

## Reference module

`defenses/mcp-boundary` is the first reference bundle. It blocks untrusted post-tool content when an instruction override is combined with secret access or external transmission indicators. Its ordinary-report control case remains allowed.
