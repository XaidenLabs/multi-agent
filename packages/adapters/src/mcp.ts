import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { DadiengClient } from "@dadieng/sdk";
import { requireAllowed } from "./errors.js";

export type McpCallTool = Client["callTool"];
export type McpToolClient = { callTool: McpCallTool };

export function protectMcpClient<T extends McpToolClient>(client: T, dadieng: DadiengClient): T {
  const guardedCallTool: McpCallTool = async (params, resultSchema, options) => {
    requireAllowed("MCP tool request", dadieng.beforeToolCall({
      tool: params.name,
      arguments: params.arguments ?? {},
      source: { type: "mcp-client", trustZone: "untrusted" },
      capability: { name: params.name },
    }));
    const result = await client.callTool(params, resultSchema, options);
    requireAllowed("MCP tool result", dadieng.afterToolResult({
      tool: params.name,
      result,
      source: { type: "mcp-server", trustZone: "untrusted" },
      capability: { name: params.name },
    }));
    return result;
  };

  return new Proxy(client, {
    get(target, property, receiver) {
      if (property === "callTool") return guardedCallTool;
      const value = Reflect.get(target, property, receiver) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
