import { describe, expect, it } from "vitest";
import { contentHash, type DefenseBundle } from "@dadieng/defense-module";
import { createMcpBoundaryBundle } from "@dadieng/defense-module/mcp-boundary";
import {
  runReplay,
  replayReportHash,
  sha256Bytes,
  verifyReplayReport,
  type ReplayRuntime,
} from "@dadieng/replay-engine";

const FIXED_TIME = "2026-09-03T15:00:00.000Z";
const environment = {
  imageDigest: sha256Bytes("dadieng-replay-worker:node22-v1"),
  dependencyLockHash: sha256Bytes("pnpm-lock-v1"),
  runtime: "node-22",
  seed: 42,
  network: "none" as const,
  filesystem: "read-only" as const,
  clock: "deterministic" as const,
};

function deterministicRuntime(durationFor: (caseId: string) => number = (caseId) => 1 + caseId.length % 5): ReplayRuntime {
  return {
    createRunId: () => "replay_test_001",
    now: () => FIXED_TIME,
    measure(caseId, operation) {
      return { value: operation(), durationMs: durationFor(caseId) };
    },
  };
}

function run(bundle: DefenseBundle = createMcpBoundaryBundle()) {
  return runReplay(bundle, { environment, runtime: deterministicRuntime() });
}

describe("deterministic replay engine", () => {
  it("passes the canonical adversarial and clean-control suite", () => {
    const report = run();

    expect(report.cases).toHaveLength(60);
    expect(report.summary.attack).toEqual({ passed: 32, failed: 0, total: 32, passRate: 1 });
    expect(report.summary.control).toEqual({ passed: 28, failed: 0, total: 28, passRate: 1 });
    expect(report.releaseEligible).toBe(true);
    expect(report.environment.network).toBe("none");
    expect(report.generator.finalDecisionBy).toBe("deterministic-assertions");
    expect(verifyReplayReport(report, createMcpBoundaryBundle())).toEqual(report);
  });

  it("reproduces the same report byte-for-byte with the same inputs", () => {
    expect(run()).toEqual(run());
  });

  it("contains results and hashes without copying hostile fixture content", () => {
    const serialized = JSON.stringify(run());

    expect(serialized).not.toContain("attacker.invalid");
    expect(serialized).not.toContain("process.env");
    expect(serialized).not.toContain("private_key");
  });

  it("detects a modified report", () => {
    const report = structuredClone(run());
    report.environment.seed = 43;

    expect(() => verifyReplayReport(report)).toThrow("Replay report hash mismatch");
  });

  it("rejects a valid report when it is paired with another bundle version", () => {
    const report = run();
    const otherBundle = structuredClone(createMcpBoundaryBundle());
    otherBundle.manifest.version = "0.2.1";

    expect(() => verifyReplayReport(report, otherBundle)).toThrow("does not match");
  });

  it("rejects a re-hashed report with a substituted suite case", () => {
    const report = structuredClone(run());
    const firstCase = report.cases[0];
    if (!firstCase) throw new Error("Expected a replay case");
    firstCase.caseId = "atk-substituted-case";
    const { reportHash: _oldHash, ...reportWithoutHash } = report;
    report.reportHash = replayReportHash(reportWithoutHash);

    expect(() => verifyReplayReport(report, createMcpBoundaryBundle())).toThrow("case list does not match");
  });

  it("fails release eligibility when a control assertion regresses", () => {
    const bundle = structuredClone(createMcpBoundaryBundle());
    const control = bundle.suite.cases.find((testCase) => testCase.kind === "control");
    if (!control) throw new Error("Expected a control case");
    control.expectedOutcome = "BLOCK";
    bundle.manifest.suiteHash = contentHash(bundle.suite);

    const report = runReplay(bundle, {
      environment,
      runtime: deterministicRuntime(),
      thresholds: { controlPassRate: 1 },
    });

    expect(report.summary.control.failed).toBe(1);
    expect(report.releaseEligible).toBe(false);
  });

  it("fails release eligibility when P95 latency exceeds the threshold", () => {
    const report = runReplay(createMcpBoundaryBundle(), {
      environment,
      runtime: deterministicRuntime(() => 51),
    });

    expect(report.summary.latencyMs).toEqual({ p50: 51, p95: 51, max: 51 });
    expect(report.releaseEligible).toBe(false);
  });

  it("rejects modules that request replay filesystem access", () => {
    const bundle = structuredClone(createMcpBoundaryBundle());
    bundle.manifest.permissions.filesystem = "temporary";

    expect(() => run(bundle)).toThrow("no filesystem permission");
  });

  it("rejects modules with an incompatible event schema", () => {
    const bundle = structuredClone(createMcpBoundaryBundle());
    bundle.manifest.compatibility.eventSchemas = ["dadieng.event.v0"];

    expect(() => run(bundle)).toThrow("incompatible with dadieng.event.v1");
  });

  it("rejects an environment that claims network access", () => {
    expect(() => runReplay(createMcpBoundaryBundle(), {
      environment: { ...environment, network: "full" as "none" },
      runtime: deterministicRuntime(),
    })).toThrow();
  });
});
