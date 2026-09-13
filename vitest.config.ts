import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@dadieng/control-plane": fileURLToPath(new URL("./apps/control-plane/src/index.ts", import.meta.url)),
      "@dadieng/validator-cli": fileURLToPath(new URL("./apps/validator-cli/src/index.ts", import.meta.url)),
      "@dadieng/contracts-client": fileURLToPath(new URL("./packages/contracts-client/src/index.ts", import.meta.url)),
      "@dadieng/defense-module/mcp-boundary": fileURLToPath(new URL("./packages/defense-module/src/mcp-boundary.ts", import.meta.url)),
      "@dadieng/defense-module": fileURLToPath(new URL("./packages/defense-module/src/index.ts", import.meta.url)),
      "@dadieng/replay-engine": fileURLToPath(new URL("./packages/replay-engine/src/index.ts", import.meta.url)),
      "@dadieng/schemas": fileURLToPath(new URL("./packages/schemas/src/index.ts", import.meta.url)),
      "@dadieng/policy-engine": fileURLToPath(new URL("./packages/policy-engine/src/index.ts", import.meta.url)),
      "@dadieng/receipt-sanitizer": fileURLToPath(new URL("./packages/receipt-sanitizer/src/index.ts", import.meta.url)),
      "@dadieng/sdk": fileURLToPath(new URL("./packages/sdk/src/index.ts", import.meta.url)),
      "@dadieng/sponsor-integrations": fileURLToPath(new URL("./packages/sponsor-integrations/src/index.ts", import.meta.url)),
      "@dadieng/multi-app-agent": fileURLToPath(new URL("./packages/multi-app-agent/src/index.ts", import.meta.url)),
      "@dadieng/adapters": fileURLToPath(new URL("./packages/adapters/src/index.ts", import.meta.url)),
      "@dadieng/indexer": fileURLToPath(new URL("./indexer/src/model.ts", import.meta.url)),
    },
  },
  test: {
    include: ["tests/**/*.test.ts"],
    coverage: {
      reporter: ["text", "html"],
    },
  },
});
