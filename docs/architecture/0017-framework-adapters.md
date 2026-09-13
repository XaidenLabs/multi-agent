# External framework adapters

## Decision

Dadieng integrates at the framework boundary instead of asking developers to
rewrite agents. `@dadieng/adapters` supports the official TypeScript MCP client
and Vercel AI SDK 7 language-model middleware and tool objects.

The MCP proxy preserves the original client surface and binds methods to the
underlying client. It evaluates arguments before `callTool` and the complete
result before returning it. The Vercel adapter uses the current v4 middleware
contract for model inputs and complete generation outputs, while its tool
wrapper enforces both sides of every `execute` call. Streaming inputs and tool
results are protected; applications that need full generated-token output
moderation must add a separately specified streaming-output policy.

## Failure behavior

Any outcome other than `ALLOW` or `OBSERVE` fails closed because these generic
adapters cannot safely implement redaction, human approval, or a sandbox on the
developer's behalf. The thrown `DadiengBlockedError` contains public IDs and an
outcome only, never the triggering content. Existing decision and incident
listeners remain available for telemetry and receipt publication.

## Adoption target

The README contains both complete integration seams. An existing client or
model needs one Dadieng instance and one wrapper call; tool definitions retain
their original fields. Installation, configuration, first protected call, and
receipt verification fit inside a fifteen-minute developer walkthrough.
