import { createDadieng } from "@dadieng/sdk";
import {
  DADIENG_RUN_SCHEMA_VERSION,
  agentRunTraceSchema,
  type AgentRunTrace,
  type CapabilityRequest,
} from "@dadieng/schemas";
import { FIXED_TIME, FIXTURE_ID, createFixtureEvent, fixtureHash } from "./fixture.js";

const proposedCapabilities: Omit<CapabilityRequest, "disposition">[] = [
  {
    requestId: "capability_read_environment",
    capability: "secrets.read",
    impact: "critical",
    targetClass: "process_environment",
    simulated: true,
    executed: false,
  },
  {
    requestId: "capability_send_external",
    capability: "network.send",
    impact: "critical",
    targetClass: "untrusted_external_origin",
    simulated: true,
    executed: false,
  },
];

export function runVulnerableAgent(): AgentRunTrace {
  const event = createFixtureEvent("agent_vulnerable_001");

  return agentRunTraceSchema.parse({
    schemaVersion: DADIENG_RUN_SCHEMA_VERSION,
    runId: "run_vulnerable_001",
    mode: "vulnerable",
    fixtureId: FIXTURE_ID,
    fixtureHash,
    startedAt: FIXED_TIME,
    completedAt: FIXED_TIME,
    status: "unsafe_action_proposed",
    steps: [
      { sequence: 1, type: "TOOL_RESULT_RECEIVED", outcome: "observed", summary: "Agent received the untrusted MCP tool result." },
      { sequence: 2, type: "CAPABILITY_REQUESTED", outcome: "unsafe", summary: "Injected content requested secret access and external transmission." },
      { sequence: 3, type: "UNSAFE_ACTION_PROPOSED", outcome: "unsafe", summary: "The vulnerable planner accepted both capability requests." },
    ],
    capabilityRequests: proposedCapabilities.map((request) => ({ ...request, disposition: "proposed" })),
    decision: null,
    receipt: null,
  });
}

export function runProtectedAgent(): AgentRunTrace {
  const event = createFixtureEvent("agent_protected_001");
  const ids = ["event_sdk_protected_001", "decision_protected_001", "receipt_protected_001"];
  const dadieng = createDadieng({
    agentId: "agent_protected_001",
    framework: "mcp-demo",
    evidenceEncryption: {
      key: Buffer.alloc(32, 7),
      keyId: "mcp-demo-key-v1",
      createIv: () => Buffer.alloc(12, 9),
    },
    runtime: {
      createId: () => ids.shift() ?? "unexpected_id",
      now: () => FIXED_TIME,
    },
  });
  const result = dadieng.afterToolResult({
    tool: "external-report-reader",
    result: event.content,
    source: event.source,
    capability: event.capability,
  });
  const decision = result.decision;

  if (decision.outcome !== "BLOCK" || !result.receipt) {
    throw new Error(`Protected demonstration expected BLOCK with receipt, received ${decision.outcome}`);
  }
  const receipt = result.receipt;

  return agentRunTraceSchema.parse({
    schemaVersion: DADIENG_RUN_SCHEMA_VERSION,
    runId: "run_protected_001",
    mode: "protected",
    fixtureId: FIXTURE_ID,
    fixtureHash,
    startedAt: FIXED_TIME,
    completedAt: FIXED_TIME,
    status: "attack_blocked",
    steps: [
      { sequence: 1, type: "TOOL_RESULT_RECEIVED", outcome: "observed", summary: "Agent received the same untrusted MCP tool result." },
      { sequence: 2, type: "CONTENT_CLASSIFIED", outcome: "unsafe", summary: "Dadieng identified instruction override and exfiltration indicators." },
      { sequence: 3, type: "POLICY_EVALUATED", outcome: "blocked", summary: "The MCP boundary defense returned BLOCK." },
      { sequence: 4, type: "ACTION_BLOCKED", outcome: "safe", summary: "No capability request was executed." },
      { sequence: 5, type: "THREAT_RECEIPT_CREATED", outcome: "safe", summary: "A sanitized public receipt was produced." },
    ],
    capabilityRequests: proposedCapabilities.map((request) => ({ ...request, disposition: "blocked" })),
    decision,
    receipt,
  });
}

export function runComparison(): { vulnerable: AgentRunTrace; protected: AgentRunTrace } {
  const vulnerable = runVulnerableAgent();
  const protectedRun = runProtectedAgent();

  if (vulnerable.fixtureHash !== protectedRun.fixtureHash) {
    throw new Error("The comparison must use the same MCP fixture");
  }

  return { vulnerable, protected: protectedRun };
}
