# `@dadieng/sdk`

The Dadieng SDK intercepts model and tool lifecycle events, normalizes them into validated Dadieng events, evaluates local Defense Modules, and creates privacy-safe Threat Receipts for blocked or observed incidents.

## Quick start

```sh
npm install @dadieng/sdk
```

```ts
import { createDadieng } from "@dadieng/sdk";

const dadieng = createDadieng({
  agentId: "agent_001",
  framework: "my-agent",
  channel: "stable",
  mode: "enforce",
  failMode: "last-known-good",
  evidenceEncryption: {
    key: await loadEvidenceKey(), // exactly 32 bytes from your secret manager
    keyId: "tenant-evidence-key-v1",
  },
});

dadieng.onDecision((decision) => {
  console.log(decision.outcome, decision.reasonCodes);
});

dadieng.onIncident((receipt, _decision, encryptedEvidence) => {
  // Publish only the receipt. Store the opaque envelope in private storage.
  console.log(receipt.evidence.hash);
  void storePrivateEvidence(receipt.evidence.encryptedUri, encryptedEvidence);
});

const result = dadieng.afterToolResult({
  tool: "external-report-reader",
  result: toolResult,
  source: {
    type: "mcp_tool_result",
    identity: "external-report-reader",
    trustZone: "untrusted",
  },
  capability: {
    name: "filesystem.write",
    impact: "high",
  },
});

if (result.decision.outcome === "BLOCK") {
  throw new Error("Dadieng blocked the tool result");
}
```

## Lifecycle hooks

- `beforeModel()` — inspect model input.
- `afterModel()` — inspect model output.
- `beforeToolCall()` — inspect a proposed tool call and arguments.
- `afterToolResult()` — inspect data returned by a tool or MCP server.
- `onDecision()` — subscribe to every local decision.
- `onIncident()` — receive a sanitized receipt and its encrypted private evidence envelope.

Decision and incident listener failures are isolated from enforcement. Diagnostics remain available through `getDiagnostics()`.

If `evidenceEncryption` is omitted, the SDK creates an in-memory ephemeral key. Production adopters should supply a managed 32-byte key so encrypted evidence remains recoverable. Reporter agent IDs are hashed by default; set `publishReporterAgentId: true` only when public attribution is intentional.

## Failure behavior

- `open`: allow when evaluation fails.
- `closed`: block when evaluation fails.
- `last-known-good`: block high/critical capabilities and observe low/medium capabilities if local evaluation fails.

## Stable channel synchronization

Configure a trusted manifest signer and the deployed Monad Registry, then synchronize before serving agent traffic:

```ts
import {
  FileSystemManifestCache,
  ManifestSynchronizer,
  createDadieng,
  createManifestChainReader,
} from "@dadieng/sdk";

const synchronizer = new ManifestSynchronizer({
  manifestUrl: "https://api.dadieng.dev/v1/channels/stable/manifest",
  signerAddress: "0x...trustedManifestSigner",
  chainId: 10143,
  registryAddress: "0x...registry",
  sdkVersion: "0.1.0",
  adapters: ["mcp"],
  failMode: "last-known-good",
}, createManifestChainReader("https://testnet-rpc.monad.xyz", 10143), undefined,
new FileSystemManifestCache("./.dadieng/cache/stable.json"));

const dadieng = createDadieng({
  agentId: "agent_001",
  framework: "my-agent",
  manifestSynchronizer: synchronizer,
});

await dadieng.syncDefenses();
```

The SDK verifies the EIP-191 signature, expiry, manifest lineage, artifact hashes, compatibility declarations, current Monad Stable state and commitments, and the complete shadow suite before replacing the active local rules. The file cache retains current and previous verified sets with owner-only permissions. On refresh failure, `last-known-good` restores the cached set, `closed` rejects the refresh, and `open` leaves the existing engine unchanged.
