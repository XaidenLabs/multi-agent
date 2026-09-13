import { createHash, randomBytes, randomUUID } from "node:crypto";
import { loadDefenseBundle } from "@dadieng/defense-module";
import { createMcpBoundaryBundle } from "@dadieng/defense-module/mcp-boundary";
import { LocalPolicyEngine, type PolicyEngineRuntime } from "@dadieng/policy-engine";
import {
  createThreatReceiptPipeline,
  type EvidenceEncryptionOptions,
} from "@dadieng/receipt-sanitizer";
import {
  DADIENG_DECISION_SCHEMA_VERSION,
  DADIENG_EVENT_SCHEMA_VERSION,
  dadiengEventSchema,
  policyDecisionSchema,
  type DadiengEvent,
  type DefenseRule,
  type EnforcementMode,
  type EncryptedThreatEvidence,
  type EventStage,
  type Impact,
  type PolicyDecision,
  type ThreatReceipt,
  type TrustZone,
} from "@dadieng/schemas";
import { ManifestSynchronizer, type ManifestSyncResult } from "./manifest-sync.js";

export * from "./manifest-sync.js";

export type DadiengFailMode = "open" | "closed" | "last-known-good";

export interface DadiengSdkRuntime extends PolicyEngineRuntime {}

export interface DadiengConfig {
  agentId: string;
  framework: string;
  sdkVersion?: string;
  channel?: string;
  mode?: EnforcementMode;
  failMode?: DadiengFailMode;
  defenses?: DefenseRule[];
  runtime?: DadiengSdkRuntime;
  evidenceEncryption?: EvidenceEncryptionOptions;
  publishReporterAgentId?: boolean;
  erc8004Id?: string;
  manifestSynchronizer?: ManifestSynchronizer;
}

export interface SourceInput {
  type?: string;
  identity?: string | undefined;
  trustZone?: TrustZone;
}

export interface CapabilityInput {
  name: string;
  impact?: Impact;
}

export interface BeforeModelInput {
  content: unknown;
  source?: SourceInput | undefined;
  capability?: CapabilityInput | undefined;
}

export interface AfterModelInput {
  content: unknown;
  source?: SourceInput | undefined;
  capability?: CapabilityInput | undefined;
}

export interface BeforeToolCallInput {
  tool: string;
  arguments: unknown;
  source?: SourceInput | undefined;
  capability?: CapabilityInput | undefined;
}

export interface AfterToolResultInput {
  tool: string;
  result: unknown;
  source?: SourceInput | undefined;
  capability?: CapabilityInput | undefined;
}

export interface ProtectionResult {
  event: DadiengEvent;
  decision: PolicyDecision;
  receipt: ThreatReceipt | null;
  encryptedEvidence: EncryptedThreatEvidence | null;
}

export interface SdkDiagnostic {
  type: "decision_listener_error" | "incident_listener_error" | "policy_evaluation_error" | "receipt_pipeline_error" | "manifest_sync_error";
  message: string;
}

export type DecisionListener = (decision: PolicyDecision, event: DadiengEvent) => void;
export type IncidentListener = (
  receipt: ThreatReceipt,
  decision: PolicyDecision,
  encryptedEvidence: EncryptedThreatEvidence,
) => void;

const defaultRuntime: DadiengSdkRuntime = {
  createId: randomUUID,
  now: () => new Date().toISOString(),
};

function hash(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function normalizeContent(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "";

  const seen = new WeakSet<object>();
  const normalized = JSON.stringify(value, (_key, current) => {
    if (!current || typeof current !== "object") return current;
    if (seen.has(current)) throw new TypeError("Dadieng hook content must not contain circular references");
    seen.add(current);
    if (Array.isArray(current)) return current;
    return Object.fromEntries(Object.entries(current).sort(([left], [right]) => left.localeCompare(right)));
  });

  return normalized ?? String(value);
}

function inferImpact(capabilityName: string): Impact {
  if (/secret|credential|private[_ -]?key|shell|payment|transfer/i.test(capabilityName)) return "critical";
  if (/write|delete|network\.send|email\.send/i.test(capabilityName)) return "high";
  if (/read|fetch|search/i.test(capabilityName)) return "medium";
  return "low";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown SDK error";
}

export class DadiengClient {
  private readonly config: Required<Omit<DadiengConfig, "defenses" | "runtime" | "evidenceEncryption" | "erc8004Id" | "manifestSynchronizer">> & {
    erc8004Id?: string;
  };
  private readonly runtime: DadiengSdkRuntime;
  private readonly evidenceEncryption: EvidenceEncryptionOptions;
  private engine: LocalPolicyEngine;
  private readonly manifestSynchronizer: ManifestSynchronizer | undefined;
  private readonly decisionListeners = new Set<DecisionListener>();
  private readonly incidentListeners = new Set<IncidentListener>();
  private readonly diagnostics: SdkDiagnostic[] = [];

  constructor(config: DadiengConfig) {
    if (!config.agentId.trim()) throw new Error("Dadieng requires an agentId");
    if (!config.framework.trim()) throw new Error("Dadieng requires a framework name");

    this.config = {
      agentId: config.agentId,
      framework: config.framework,
      sdkVersion: config.sdkVersion ?? "0.1.0",
      channel: config.channel ?? "stable",
      mode: config.mode ?? "enforce",
      failMode: config.failMode ?? "last-known-good",
      publishReporterAgentId: config.publishReporterAgentId ?? false,
      ...(config.erc8004Id ? { erc8004Id: config.erc8004Id } : {}),
    };
    this.runtime = config.runtime ?? defaultRuntime;
    this.evidenceEncryption = config.evidenceEncryption ?? {
      key: randomBytes(32),
      keyId: "local-ephemeral-v1",
    };
    this.manifestSynchronizer = config.manifestSynchronizer;
    this.engine = new LocalPolicyEngine(
      config.defenses ?? [loadDefenseBundle(createMcpBoundaryBundle())],
      this.runtime,
    );
  }

  beforeModel(input: BeforeModelInput): ProtectionResult {
    return this.protect("before_model", input.content, input.source, input.capability, "application_input", "trusted");
  }

  afterModel(input: AfterModelInput): ProtectionResult {
    return this.protect("after_model", input.content, input.source, input.capability, "model_output", "tenant");
  }

  beforeToolCall(input: BeforeToolCallInput): ProtectionResult {
    return this.protect("before_tool", input.arguments, input.source, input.capability ?? { name: input.tool }, "agent_tool_call", "tenant");
  }

  afterToolResult(input: AfterToolResultInput): ProtectionResult {
    return this.protect("after_tool", input.result, input.source, input.capability ?? { name: input.tool }, "mcp_tool_result", "untrusted");
  }

  onDecision(listener: DecisionListener): () => void {
    this.decisionListeners.add(listener);
    return () => this.decisionListeners.delete(listener);
  }

  onIncident(listener: IncidentListener): () => void {
    this.incidentListeners.add(listener);
    return () => this.incidentListeners.delete(listener);
  }

  getDiagnostics(): readonly SdkDiagnostic[] {
    return [...this.diagnostics];
  }

  async syncDefenses(): Promise<ManifestSyncResult> {
    if (!this.manifestSynchronizer) throw new Error("Dadieng manifest synchronization is not configured");
    try {
      return await this.manifestSynchronizer.sync((defenses) => {
        this.engine = new LocalPolicyEngine(defenses, this.runtime);
      });
    } catch (error) {
      this.diagnostics.push({ type: "manifest_sync_error", message: errorMessage(error) });
      throw error;
    }
  }

  private protect(
    stage: EventStage,
    rawContent: unknown,
    source: SourceInput | undefined,
    capability: CapabilityInput | undefined,
    defaultSourceType: string,
    defaultTrustZone: TrustZone,
  ): ProtectionResult {
    let content: string;
    let normalizationFailed = false;
    try {
      content = normalizeContent(rawContent);
    } catch (error) {
      content = "[content normalization failed]";
      normalizationFailed = true;
      this.diagnostics.push({ type: "policy_evaluation_error", message: errorMessage(error) });
    }

    const capabilityName = capability?.name ?? "content.inspect";
    const event = dadiengEventSchema.parse({
      schemaVersion: DADIENG_EVENT_SCHEMA_VERSION,
      eventId: this.runtime.createId(),
      timestamp: this.runtime.now(),
      agent: {
        agentId: this.config.agentId,
        framework: this.config.framework,
        sdkVersion: this.config.sdkVersion,
      },
      stage,
      source: {
        type: source?.type ?? defaultSourceType,
        ...(source?.identity ? { identity: source.identity } : {}),
        trustZone: source?.trustZone ?? defaultTrustZone,
      },
      capability: {
        name: capabilityName,
        impact: capability?.impact ?? inferImpact(capabilityName),
      },
      content,
      contentReferences: [{ type: `${stage}_content`, fingerprint: hash(content) }],
      policyContext: { channel: this.config.channel, mode: this.config.mode },
    });

    let decision: PolicyDecision;
    if (normalizationFailed) {
      decision = this.failureDecision(event);
    } else {
      try {
        decision = this.engine.evaluate(event);
      } catch (error) {
        this.diagnostics.push({ type: "policy_evaluation_error", message: errorMessage(error) });
        decision = this.failureDecision(event);
      }
    }

    this.emitDecision(decision, event);

    let incident: ReturnType<typeof createThreatReceiptPipeline> | null = null;
    if (decision.outcome === "BLOCK" || decision.outcome === "OBSERVE") {
      try {
        incident = createThreatReceiptPipeline(event, decision, {
          createId: () => this.runtime.createId(),
          encryption: this.evidenceEncryption,
          publishReporterAgentId: this.config.publishReporterAgentId,
          ...(this.config.erc8004Id ? { erc8004Id: this.config.erc8004Id } : {}),
        });
      } catch (error) {
        this.diagnostics.push({ type: "receipt_pipeline_error", message: errorMessage(error) });
      }
    }
    const receipt = incident?.receipt ?? null;
    const encryptedEvidence = incident?.encryptedEvidence ?? null;

    if (receipt && encryptedEvidence) this.emitIncident(receipt, decision, encryptedEvidence);
    return { event, decision, receipt, encryptedEvidence };
  }

  private failureDecision(event: DadiengEvent): PolicyDecision {
    const outcome = this.config.failMode === "open"
      ? "ALLOW"
      : this.config.failMode === "closed"
        ? "BLOCK"
        : event.capability?.impact === "critical" || event.capability?.impact === "high"
          ? "BLOCK"
          : "OBSERVE";

    return policyDecisionSchema.parse({
      schemaVersion: DADIENG_DECISION_SCHEMA_VERSION,
      decisionId: this.runtime.createId(),
      eventId: event.eventId,
      outcome,
      reasonCodes: [`SDK_EVALUATION_FAILED_${this.config.failMode.replaceAll("-", "_").toUpperCase()}`],
      matchedDefenseIds: [],
      evaluatedAt: this.runtime.now(),
    });
  }

  private emitDecision(decision: PolicyDecision, event: DadiengEvent): void {
    for (const listener of this.decisionListeners) {
      try {
        listener(decision, event);
      } catch (error) {
        this.diagnostics.push({ type: "decision_listener_error", message: errorMessage(error) });
      }
    }
  }

  private emitIncident(
    receipt: ThreatReceipt,
    decision: PolicyDecision,
    encryptedEvidence: EncryptedThreatEvidence,
  ): void {
    for (const listener of this.incidentListeners) {
      try {
        listener(receipt, decision, encryptedEvidence);
      } catch (error) {
        this.diagnostics.push({ type: "incident_listener_error", message: errorMessage(error) });
      }
    }
  }
}

export function createDadieng(config: DadiengConfig): DadiengClient {
  return new DadiengClient(config);
}
