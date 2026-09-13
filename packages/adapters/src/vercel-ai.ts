import type { DadiengClient } from "@dadieng/sdk";
import type { LanguageModelMiddleware } from "ai";
import { requireAllowed } from "./errors.js";

export function createDadiengLanguageModelMiddleware(dadieng: DadiengClient): LanguageModelMiddleware {
  return {
    specificationVersion: "v4",
    transformParams: async ({ params }) => {
      requireAllowed("AI SDK model input", dadieng.beforeModel({
        content: params.prompt,
        source: { type: "vercel-ai-sdk", trustZone: "tenant" },
        capability: { name: "model.generate", impact: "medium" },
      }));
      return params;
    },
    wrapGenerate: async ({ doGenerate }) => {
      const result = await doGenerate();
      requireAllowed("AI SDK model output", dadieng.afterModel({
        content: result.content,
        source: { type: "vercel-ai-sdk", trustZone: "untrusted" },
        capability: { name: "model.generate", impact: "medium" },
      }));
      return result;
    },
  };
}

type ExecutableTool<TInput, TOutput> = {
  execute: (input: TInput, options: unknown) => Promise<TOutput> | TOutput;
};

export function protectAiSdkTool<TInput, TOutput, TTool extends ExecutableTool<TInput, TOutput>>(
  dadieng: DadiengClient,
  name: string,
  tool: TTool,
): TTool {
  return {
    ...tool,
    async execute(input: TInput, options: unknown) {
      requireAllowed("AI SDK tool request", dadieng.beforeToolCall({
        tool: name,
        arguments: input,
        source: { type: "vercel-ai-sdk", trustZone: "tenant" },
        capability: { name },
      }));
      const result = await tool.execute(input, options);
      requireAllowed("AI SDK tool result", dadieng.afterToolResult({
        tool: name,
        result,
        source: { type: "vercel-ai-sdk-tool", trustZone: "untrusted" },
        capability: { name },
      }));
      return result;
    },
  } as TTool;
}
