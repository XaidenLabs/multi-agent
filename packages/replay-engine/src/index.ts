import { createHash, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import {
  contentHash,
  loadDefenseBundle,
  verifyDefenseBundle,
  type DefenseBundle,
} from "@dadieng/defense-module";
import {
  DADIENG_EVENT_SCHEMA_VERSION,
  DADIENG_REPLAY_SCHEMA_VERSION,
  replayEnvironmentSchema,
  replayReportSchema,
  type DecisionOutcome,
  type ReplayReport,
} from "@dadieng/schemas";

export interface ReplayMeasurement<T> {
  value: T;
  durationMs: number;
}

export interface ReplayRuntime {
  createRunId(): string;
  now(): string;
  measure<T>(caseId: string, operation: () => T): ReplayMeasurement<T>;
}

export interface ReplayThresholds {
  attackPassRate: number;
  controlPassRate: number;
  p95LatencyMs: number;
}

export interface RunReplayOptions {
  environment: ReplayReport["environment"];
  thresholds?: Partial<ReplayThresholds> | undefined;
  runtime?: ReplayRuntime | undefined;
  generator?: ReplayReport["generator"] | undefined;
}

const DEFAULT_THRESHOLDS: ReplayThresholds = {
  attackPassRate: 0.95,
  controlPassRate: 0.95,
  p95LatencyMs: 50,
};

const defaultRuntime: ReplayRuntime = {
  createRunId: randomUUID,
  now: () => new Date().toISOString(),
  measure(_caseId, operation) {
    const startedAt = performance.now();
    const value = operation();
    const durationMs = Math.round((performance.now() - startedAt) * 1_000) / 1_000;
    return { value, durationMs };
  },
};

function percentile(values: number[], percentage: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.max(0, Math.ceil(percentage * sorted.length) - 1);
  return sorted[index] ?? 0;
}

function summarize(cases: ReplayReport["cases"], kind: "attack" | "control") {
  const selected = cases.filter((testCase) => testCase.kind === kind);
  const passed = selected.filter((testCase) => testCase.passed).length;
  return {
    passed,
    failed: selected.length - passed,
    total: selected.length,
    passRate: selected.length === 0 ? 0 : passed / selected.length,
  };
}

function latencySummary(cases: ReplayReport["cases"]): ReplayReport["summary"]["latencyMs"] {
  const durations = cases.map((testCase) => testCase.durationMs);
  return {
    p50: percentile(durations, 0.5),
    p95: percentile(durations, 0.95),
    max: durations.length === 0 ? 0 : Math.max(...durations),
  };
}

export function replayReportHash(report: Omit<ReplayReport, "reportHash">): string {
  return contentHash(report);
}

export function sha256Bytes(value: string | Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function runReplay(bundleInput: DefenseBundle, options: RunReplayOptions): ReplayReport {
  const bundle = verifyDefenseBundle(bundleInput);
  const environment = replayEnvironmentSchema.parse(options.environment);
  if (bundle.manifest.permissions.filesystem !== "none") {
    throw new Error("Canonical replay requires a Defense Module with no filesystem permission");
  }
  if (!bundle.manifest.compatibility.eventSchemas.includes(DADIENG_EVENT_SCHEMA_VERSION)) {
    throw new Error(`Defense Module is incompatible with ${DADIENG_EVENT_SCHEMA_VERSION}`);
  }
  if (bundle.suite.cases.every((testCase) => testCase.kind !== "attack")
    || bundle.suite.cases.every((testCase) => testCase.kind !== "control")) {
    throw new Error("Canonical replay requires at least one attack and one control case");
  }

  const runtime = options.runtime ?? defaultRuntime;
  const thresholds = { ...DEFAULT_THRESHOLDS, ...options.thresholds };
  const defense = loadDefenseBundle(bundle);
  const runId = runtime.createRunId();
  const startedAt = runtime.now();
  const cases: ReplayReport["cases"] = bundle.suite.cases.map((testCase) => {
    const measurement = runtime.measure(testCase.caseId, () => defense.evaluate({
      schemaVersion: DADIENG_EVENT_SCHEMA_VERSION,
      eventId: `${runId}:${testCase.caseId}`,
      timestamp: "1970-01-01T00:00:00.000Z",
      agent: { agentId: "dadieng.replay-worker", framework: "dadieng", sdkVersion: "0.1.0" },
      stage: testCase.stage,
      source: { type: "replay_fixture", trustZone: testCase.trustZone },
      content: testCase.content,
      contentReferences: [{ type: "replay_fixture", fingerprint: contentHash(testCase.content) }],
      policyContext: { channel: "candidate", mode: "enforce" },
    }));
    const actualOutcome: DecisionOutcome = measurement.value?.outcome ?? "ALLOW";

    return {
      caseId: testCase.caseId,
      kind: testCase.kind,
      expectedOutcome: testCase.expectedOutcome,
      actualOutcome,
      passed: actualOutcome === testCase.expectedOutcome,
      durationMs: measurement.durationMs,
      reasonCodes: measurement.value?.reasonCodes ?? ["NO_DEFENSE_MATCH"],
    };
  });

  const attack = summarize(cases, "attack");
  const control = summarize(cases, "control");
  const latencyMs = latencySummary(cases);
  const releaseEligible = attack.passRate >= thresholds.attackPassRate
    && control.passRate >= thresholds.controlPassRate
    && latencyMs.p95 <= thresholds.p95LatencyMs;
  const reportWithoutHash: Omit<ReplayReport, "reportHash"> = {
    schemaVersion: DADIENG_REPLAY_SCHEMA_VERSION,
    runId,
    defenseVersionId: `${bundle.manifest.defenseId}@${bundle.manifest.version}`,
    startedAt,
    completedAt: runtime.now(),
    environment,
    artifacts: {
      manifestHash: bundle.manifestHash,
      artifactHash: bundle.manifest.artifactHash,
      suiteHash: bundle.manifest.suiteHash,
      sbomHash: bundle.manifest.sbomHash,
    },
    thresholds,
    summary: { attack, control, latencyMs },
    cases,
    generator: options.generator ?? {
      qwenUsed: false,
      generatedCases: 0,
      finalDecisionBy: "deterministic-assertions",
    },
    releaseEligible,
  };

  return replayReportSchema.parse({
    ...reportWithoutHash,
    reportHash: replayReportHash(reportWithoutHash),
  });
}

export function verifyReplayReport(reportInput: ReplayReport, bundleInput?: DefenseBundle): ReplayReport {
  const report = replayReportSchema.parse(reportInput);
  const { reportHash, ...reportWithoutHash } = report;
  if (replayReportHash(reportWithoutHash) !== reportHash) {
    throw new Error("Replay report hash mismatch");
  }

  const latency = latencySummary(report.cases);
  if (latency.p50 !== report.summary.latencyMs.p50
    || latency.p95 !== report.summary.latencyMs.p95
    || latency.max !== report.summary.latencyMs.max) {
    throw new Error("Replay latency summary mismatch");
  }

  if (bundleInput) {
    const bundle = verifyDefenseBundle(bundleInput);
    if (report.defenseVersionId !== `${bundle.manifest.defenseId}@${bundle.manifest.version}`
      || report.artifacts.manifestHash !== bundle.manifestHash
      || report.artifacts.artifactHash !== bundle.manifest.artifactHash
      || report.artifacts.suiteHash !== bundle.manifest.suiteHash
      || report.artifacts.sbomHash !== bundle.manifest.sbomHash) {
      throw new Error("Replay report does not match the Defense Module bundle");
    }
    if (report.cases.length !== bundle.suite.cases.length
      || report.cases.some((result, index) => {
        const declared = bundle.suite.cases[index];
        return !declared
          || result.caseId !== declared.caseId
          || result.kind !== declared.kind
          || result.expectedOutcome !== declared.expectedOutcome;
      })) {
      throw new Error("Replay report case list does not match the committed suite");
    }
  }

  return report;
}
