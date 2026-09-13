import { createMcpBoundaryBundle } from "@dadieng/defense-module/mcp-boundary";
import { runReplay, sha256Bytes, type ReplayRuntime } from "./index.js";

const FIXED_TIME = "2026-09-03T15:00:00.000Z";

export function createMcpReferenceReport(lockfile: Uint8Array) {
  const runtime: ReplayRuntime = {
    createRunId: () => "replay_mcp_boundary_001",
    now: () => FIXED_TIME,
    measure(caseId, operation) {
      const value = operation();
      const durationMs = 1 + (caseId.length % 5);
      return { value, durationMs };
    },
  };

  return runReplay(createMcpBoundaryBundle(), {
    runtime,
    environment: {
      imageDigest: sha256Bytes("dadieng-replay-worker:node22-v1"),
      dependencyLockHash: sha256Bytes(lockfile),
      runtime: "node-22",
      seed: 42,
      network: "none",
      filesystem: "read-only",
      clock: "deterministic",
    },
  });
}
