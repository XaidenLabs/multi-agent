# Dadieng framework adapters

Add Dadieng to an existing TypeScript agent without replacing its framework.
Both adapters enforce locally before a tool request leaves the process and
again before an untrusted result returns to the model.

## MCP client

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { protectMcpClient } from "@dadieng/adapters";
import { createDadieng } from "@dadieng/sdk";

const rawClient = new Client({ name: "my-agent", version: "1.0.0" });
const dadieng = createDadieng({ agentId: "my-agent", framework: "mcp" });
const client = protectMcpClient(rawClient, dadieng);

// Connect normally. Every client.callTool(...) is now guarded.
```

## Vercel AI SDK

```ts
import { generateText, wrapLanguageModel } from "ai";
import { createDadiengLanguageModelMiddleware, protectAiSdkTool } from "@dadieng/adapters";
import { createDadieng } from "@dadieng/sdk";

const dadieng = createDadieng({ agentId: "my-agent", framework: "vercel-ai" });
const protectedModel = wrapLanguageModel({
  model,
  middleware: createDadiengLanguageModelMiddleware(dadieng),
});
const protectedSearch = protectAiSdkTool(dadieng, "search", searchTool);

await generateText({ model: protectedModel, tools: { search: protectedSearch }, prompt: "..." });
```

`DadiengBlockedError` includes only a decision ID, optional sanitized receipt
ID, and outcome. It never copies the hostile content into the exception.
