import { z } from "zod";

export const DADIENG_EVENT_SCHEMA_VERSION = "dadieng.event.v1" as const;
export const DADIENG_DECISION_SCHEMA_VERSION = "dadieng.decision.v1" as const;
export const DADIENG_RECEIPT_SCHEMA_VERSION = "dadieng.receipt.v2" as const;
export const DADIENG_TAXONOMY_SCHEMA_VERSION = "dadieng.attack-taxonomy.v1" as const;
export const DADIENG_PRIVATE_EVIDENCE_SCHEMA_VERSION = "dadieng.private-evidence.v1" as const;
export const DADIENG_ENCRYPTED_EVIDENCE_SCHEMA_VERSION = "dadieng.encrypted-evidence.v1" as const;
export const DADIENG_DEFENSE_SCHEMA_VERSION = "dadieng.defense.v1" as const;
export const DADIENG_REPLAY_SCHEMA_VERSION = "dadieng.replay-report.v2" as const;
export const DADIENG_ATTESTATION_SCHEMA_VERSION = "dadieng.attestation.v1" as const;
export const DADIENG_MANIFEST_SCHEMA_VERSION = "dadieng.stable-manifest.v1" as const;
export const DADIENG_RUN_SCHEMA_VERSION = "dadieng.agent-run.v1" as const;
export const DADIENG_DEFENSE_ARTIFACT_SCHEMA_VERSION = "dadieng.defense-artifact.v1" as const;
export const DADIENG_SBOM_SCHEMA_VERSION = "dadieng.sbom.v1" as const;
export const DADIENG_SUITE_SCHEMA_VERSION = "dadieng.replay-suite.v1" as const;

export const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/, "Expected a sha256 content hash");
export const reasonCodeSchema = z.string().regex(/^[A-Z][A-Z0-9_]{0,127}$/, "Expected a controlled reason code");
export const publicIdentifierSchema = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/, "Expected a public-safe identifier");
export const timestampSchema = z.string().datetime({ offset: true });
export const trustZoneSchema = z.enum(["trusted", "tenant", "external", "untrusted"]);
export const eventStageSchema = z.enum(["before_model", "after_model", "before_tool", "after_tool"]);
export const impactSchema = z.enum(["low", "medium", "high", "critical"]);
export const enforcementModeSchema = z.enum(["observe", "enforce"]);
export const decisionOutcomeSchema = z.enum([
  "ALLOW",
  "BLOCK",
  "REDACT",
  "REQUIRE_APPROVAL",
  "SANDBOX",
  "OBSERVE",
]);
export const attackClassSchema = z.enum([
  "prompt_injection",
  "tool_poisoning",
  "privilege_escalation",
  "data_exfiltration",
  "malicious_module",
]);
export const capabilityClassSchema = z.enum([
  "secrets.read",
  "network.send",
  "filesystem.read",
  "filesystem.write",
  "process.execute",
  "payment.transfer",
  "communications.send",
  "data.read",
  "data.write",
  "content.inspect",
  "unknown",
]);
export const agentFrameworkSchema = z.enum(["vercel-ai", "langchain", "mcp", "custom", "unknown"]);
export const adapterSchema = z.enum(["mcp", "vercel-ai", "langchain", "custom", "unknown"]);

export const dadiengEventSchema = z.object({
  schemaVersion: z.literal(DADIENG_EVENT_SCHEMA_VERSION),
  eventId: z.string().min(1),
  timestamp: timestampSchema,
  agent: z.object({
    agentId: z.string().min(1),
    framework: z.string().min(1),
    sdkVersion: z.string().min(1),
  }),
  stage: eventStageSchema,
  source: z.object({
    type: z.string().min(1),
    identity: z.string().min(1).optional(),
    trustZone: trustZoneSchema,
  }),
  capability: z.object({
    name: z.string().min(1),
    impact: impactSchema,
  }).optional(),
  content: z.string(),
  contentReferences: z.array(z.object({
    type: z.string().min(1),
    fingerprint: hashSchema,
  })),
  policyContext: z.object({
    channel: z.string().min(1),
    mode: enforcementModeSchema,
  }),
});

export const policyDecisionSchema = z.object({
  schemaVersion: z.literal(DADIENG_DECISION_SCHEMA_VERSION),
  decisionId: z.string().min(1),
  eventId: z.string().min(1),
  outcome: decisionOutcomeSchema,
  reasonCodes: z.array(reasonCodeSchema).min(1),
  matchedDefenseIds: z.array(z.string().min(1)),
  evaluatedAt: timestampSchema,
});

export const threatReceiptSchema = z.object({
  schemaVersion: z.literal(DADIENG_RECEIPT_SCHEMA_VERSION),
  receiptId: z.string().min(1),
  observedAt: timestampSchema,
  reporter: z.object({
    agentId: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/).optional(),
    agentFingerprint: hashSchema,
    erc8004Id: z.string().regex(/^\d+$/).optional(),
    sdkVersion: z.string().min(1).max(40),
  }),
  classification: z.object({
    taxonomyVersion: z.literal(DADIENG_TAXONOMY_SCHEMA_VERSION),
    attackClass: attackClassSchema,
    severity: impactSchema,
    confidence: z.number().min(0).max(1),
  }),
  surface: z.object({
    framework: agentFrameworkSchema,
    adapter: adapterSchema,
    capabilities: z.array(capabilityClassSchema).min(1),
  }),
  source: z.object({
    trustZone: trustZoneSchema,
    fingerprint: hashSchema,
  }),
  sanitized: z.object({
    summary: z.string().min(1).max(500),
    replayFixtureUri: z.string().regex(/^(local|ipfs):\/\/[A-Za-z0-9._~:/-]+$/).optional(),
  }),
  evidence: z.object({
    hash: hashSchema,
    encryptedUri: z.string().regex(/^(local|s3|ipfs):\/\/[A-Za-z0-9._~:/-]+$/),
    encryption: z.literal("aes-256-gcm-v1"),
    keyId: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/),
  }),
  deduplicationKey: hashSchema,
  privacy: z.object({
    containsRawPrompt: z.literal(false),
    containsCredentials: z.literal(false),
    containsPersonalData: z.literal(false),
    redactionPolicy: z.literal("dadieng.strict-redaction.v1"),
    sanitizationConfidence: z.number().min(0).max(1),
    manualReviewRequired: z.boolean(),
  }),
}).superRefine((receipt, context) => {
  if ((receipt.classification.severity === "high" || receipt.classification.severity === "critical")
    && !receipt.privacy.manualReviewRequired) {
    context.addIssue({
      code: "custom",
      path: ["privacy", "manualReviewRequired"],
      message: "High and critical receipts require manual review before public disclosure",
    });
  }
});

export const privateThreatEvidenceSchema = z.object({
  schemaVersion: z.literal(DADIENG_PRIVATE_EVIDENCE_SCHEMA_VERSION),
  receiptId: z.string().min(1),
  capturedAt: timestampSchema,
  event: dadiengEventSchema,
  decision: policyDecisionSchema,
});

const base64Schema = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/);

export const encryptedThreatEvidenceSchema = z.object({
  schemaVersion: z.literal(DADIENG_ENCRYPTED_EVIDENCE_SCHEMA_VERSION),
  receiptId: z.string().min(1),
  algorithm: z.literal("aes-256-gcm-v1"),
  keyId: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/),
  iv: base64Schema,
  ciphertext: base64Schema,
  authTag: base64Schema,
});

export const defenseManifestSchema = z.object({
  schemaVersion: z.literal(DADIENG_DEFENSE_SCHEMA_VERSION),
  defenseId: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/, "Expected a semantic version"),
  name: z.string().min(1),
  authorAgentId: z.string().min(1),
  runtime: z.enum(["dadieng-rules", "typescript", "wasm"]),
  entrypoint: z.string().min(1),
  permissions: z.object({
    network: z.literal(false),
    filesystem: z.enum(["none", "temporary"]),
    clock: z.literal(false),
  }),
  compatibility: z.object({
    sdk: z.string().min(1),
    adapters: z.array(z.string().min(1)),
    eventSchemas: z.array(z.string().min(1)).min(1),
  }),
  expectedOutcomes: z.array(decisionOutcomeSchema).min(1),
  artifactHash: hashSchema,
  suiteHash: hashSchema,
  sbomHash: hashSchema,
});

export const defenseArtifactSchema = z.object({
  schemaVersion: z.literal(DADIENG_DEFENSE_ARTIFACT_SCHEMA_VERSION),
  defenseId: z.string().min(1),
  rules: z.array(z.object({
    ruleId: publicIdentifierSchema,
    description: z.string().min(1),
    stages: z.array(eventStageSchema).min(1),
    trustZones: z.array(trustZoneSchema).min(1),
    indicatorGroups: z.array(z.array(z.string().min(1).max(160)).min(1)).min(1),
    outcome: decisionOutcomeSchema,
    reasonCodes: z.array(reasonCodeSchema).min(1),
  })).min(1),
});

export const defenseSbomSchema = z.object({
  schemaVersion: z.literal(DADIENG_SBOM_SCHEMA_VERSION),
  defenseId: z.string().min(1),
  format: z.literal("dadieng-sbom-v1"),
  packages: z.array(z.object({
    name: z.string().min(1),
    version: z.string().min(1),
    license: z.string().min(1),
  })),
});

export const defenseTestSuiteSchema = z.object({
  schemaVersion: z.literal(DADIENG_SUITE_SCHEMA_VERSION),
  defenseId: z.string().min(1),
  cases: z.array(z.object({
    caseId: publicIdentifierSchema,
    kind: z.enum(["attack", "control"]),
    stage: eventStageSchema,
    trustZone: trustZoneSchema,
    content: z.string(),
    expectedOutcome: decisionOutcomeSchema,
  })).min(1),
}).superRefine((suite, context) => {
  const caseIds = new Set<string>();
  for (const testCase of suite.cases) {
    if (caseIds.has(testCase.caseId)) {
      context.addIssue({ code: "custom", message: `Duplicate test case ID ${testCase.caseId}` });
    }
    caseIds.add(testCase.caseId);
  }
});

const replayResultSummarySchema = z.object({
  passed: z.number().int().nonnegative(),
  failed: z.number().int().nonnegative(),
  total: z.number().int().positive(),
  passRate: z.number().min(0).max(1),
}).superRefine((result, context) => {
  if (result.passed + result.failed !== result.total) {
    context.addIssue({ code: "custom", message: "passed + failed must equal total" });
  }
  if (Math.abs(result.passRate - result.passed / result.total) > Number.EPSILON) {
    context.addIssue({ code: "custom", message: "passRate must equal passed / total" });
  }
});

export const replayEnvironmentSchema = z.object({
  imageDigest: hashSchema,
  dependencyLockHash: hashSchema,
  runtime: z.string().min(1),
  seed: z.number().int().nonnegative(),
  network: z.literal("none"),
  filesystem: z.literal("read-only"),
  clock: z.literal("deterministic"),
});

export const replayReportSchema = z.object({
  schemaVersion: z.literal(DADIENG_REPLAY_SCHEMA_VERSION),
  runId: z.string().min(1),
  defenseVersionId: z.string().min(1),
  startedAt: timestampSchema,
  completedAt: timestampSchema,
  environment: replayEnvironmentSchema,
  artifacts: z.object({
    manifestHash: hashSchema,
    artifactHash: hashSchema,
    suiteHash: hashSchema,
    sbomHash: hashSchema,
  }),
  thresholds: z.object({
    attackPassRate: z.number().min(0).max(1),
    controlPassRate: z.number().min(0).max(1),
    p95LatencyMs: z.number().nonnegative(),
  }),
  summary: z.object({
    attack: replayResultSummarySchema,
    control: replayResultSummarySchema,
    latencyMs: z.object({
      p50: z.number().nonnegative(),
      p95: z.number().nonnegative(),
      max: z.number().nonnegative(),
    }),
  }),
  cases: z.array(z.object({
    caseId: publicIdentifierSchema,
    kind: z.enum(["attack", "control"]),
    expectedOutcome: decisionOutcomeSchema,
    actualOutcome: decisionOutcomeSchema,
    passed: z.boolean(),
    durationMs: z.number().finite().nonnegative(),
    reasonCodes: z.array(reasonCodeSchema),
  })).min(2),
  generator: z.object({
    qwenUsed: z.boolean(),
    generatedCases: z.number().int().nonnegative(),
    finalDecisionBy: z.literal("deterministic-assertions"),
  }),
  releaseEligible: z.boolean(),
  reportHash: hashSchema,
}).superRefine((report, context) => {
  const attackCases = report.cases.filter((testCase) => testCase.kind === "attack");
  const controlCases = report.cases.filter((testCase) => testCase.kind === "control");
  const summaries = [[attackCases, report.summary.attack], [controlCases, report.summary.control]] as const;

  for (const [cases, summary] of summaries) {
    const passed = cases.filter((testCase) => testCase.passed).length;
    if (summary.total !== cases.length || summary.passed !== passed || summary.failed !== cases.length - passed) {
      context.addIssue({ code: "custom", message: "Replay summary must match case results" });
    }
  }
  for (const testCase of report.cases) {
    if (testCase.passed !== (testCase.expectedOutcome === testCase.actualOutcome)) {
      context.addIssue({ code: "custom", message: `Replay case ${testCase.caseId} has an inconsistent assertion` });
    }
  }
  if (new Set(report.cases.map((testCase) => testCase.caseId)).size !== report.cases.length) {
    context.addIssue({ code: "custom", message: "Replay report case IDs must be unique" });
  }
  if (!report.generator.qwenUsed && report.generator.generatedCases !== 0) {
    context.addIssue({ code: "custom", message: "generatedCases must be zero when Qwen was not used" });
  }
  if (Date.parse(report.completedAt) < Date.parse(report.startedAt)) {
    context.addIssue({ code: "custom", message: "Replay completion cannot precede its start" });
  }
  if (report.summary.latencyMs.p50 > report.summary.latencyMs.p95
    || report.summary.latencyMs.p95 > report.summary.latencyMs.max) {
    context.addIssue({ code: "custom", message: "Replay latency percentiles must be ordered" });
  }
  const eligible = report.summary.attack.passRate >= report.thresholds.attackPassRate
    && report.summary.control.passRate >= report.thresholds.controlPassRate
    && report.summary.latencyMs.p95 <= report.thresholds.p95LatencyMs;
  if (report.releaseEligible !== eligible) {
    context.addIssue({ code: "custom", message: "releaseEligible must match replay thresholds" });
  }
});

export const validatorAttestationSchema = z.object({
  schemaVersion: z.literal(DADIENG_ATTESTATION_SCHEMA_VERSION),
  attestationId: z.string().min(1),
  validatorAgentId: z.string().min(1),
  chainId: z.number().int().positive(),
  registryAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  defenseVersionId: z.string().min(1),
  artifactHash: hashSchema,
  suiteHash: hashSchema,
  reportHash: hashSchema,
  passed: z.boolean(),
  signedAt: timestampSchema,
  signature: z.string().min(1),
});

export function validatorAttestationSigningMessage(
  attestation: Omit<ValidatorAttestation, "signature">,
): string {
  return [
    DADIENG_ATTESTATION_SCHEMA_VERSION,
    `attestationId=${attestation.attestationId}`,
    `validatorAgentId=${attestation.validatorAgentId}`,
    `chainId=${attestation.chainId}`,
    `registryAddress=${attestation.registryAddress.toLowerCase()}`,
    `defenseVersionId=${attestation.defenseVersionId}`,
    `artifactHash=${attestation.artifactHash}`,
    `suiteHash=${attestation.suiteHash}`,
    `reportHash=${attestation.reportHash}`,
    `passed=${attestation.passed}`,
    `signedAt=${attestation.signedAt}`,
  ].join("\n");
}

export const stableManifestSchema = z.object({
  schemaVersion: z.literal(DADIENG_MANIFEST_SCHEMA_VERSION),
  channel: z.string().min(1),
  generatedAt: timestampSchema,
  expiresAt: timestampSchema,
  chainId: z.number().int().positive(),
  registryAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  versions: z.array(z.object({
    defenseId: z.string().min(1),
    version: z.string().regex(/^\d+\.\d+\.\d+$/),
    artifactHash: hashSchema,
    artifactUri: z.string().regex(/^https?:\/\//),
    status: z.literal("stable"),
  })),
  previousManifestHash: hashSchema.nullable(),
  signature: z.string().regex(/^0x[a-fA-F0-9]{130}$/),
}).superRefine((manifest, context) => {
  if (Date.parse(manifest.expiresAt) <= Date.parse(manifest.generatedAt)) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "Manifest expiry must follow generation" });
  }
  const identities = manifest.versions.map((version) => `${version.defenseId}@${version.version}`);
  if (new Set(identities).size !== identities.length) {
    context.addIssue({ code: "custom", path: ["versions"], message: "Stable manifest versions must be unique" });
  }
  if (new Set(manifest.versions.map((version) => version.defenseId)).size !== manifest.versions.length) {
    context.addIssue({ code: "custom", path: ["versions"], message: "A stable manifest may activate only one version per defense" });
  }
});

export function stableManifestSigningMessage(manifest: Omit<StableManifest, "signature">): string {
  const versions = [...manifest.versions]
    .sort((left, right) => left.defenseId.localeCompare(right.defenseId) || left.version.localeCompare(right.version));
  return JSON.stringify({ ...manifest, versions });
}

export const capabilityRequestSchema = z.object({
  requestId: z.string().min(1),
  capability: z.string().min(1),
  impact: impactSchema,
  targetClass: z.string().min(1),
  disposition: z.enum(["proposed", "blocked"]),
  simulated: z.literal(true),
  executed: z.literal(false),
});

export const agentTraceStepSchema = z.object({
  sequence: z.number().int().positive(),
  type: z.enum([
    "TOOL_RESULT_RECEIVED",
    "CONTENT_CLASSIFIED",
    "CAPABILITY_REQUESTED",
    "POLICY_EVALUATED",
    "ACTION_BLOCKED",
    "UNSAFE_ACTION_PROPOSED",
    "THREAT_RECEIPT_CREATED",
  ]),
  outcome: z.enum(["observed", "safe", "unsafe", "blocked"]),
  summary: z.string().min(1).max(240),
});

export const agentRunTraceSchema = z.object({
  schemaVersion: z.literal(DADIENG_RUN_SCHEMA_VERSION),
  runId: z.string().min(1),
  mode: z.enum(["vulnerable", "protected"]),
  fixtureId: z.string().min(1),
  fixtureHash: hashSchema,
  startedAt: timestampSchema,
  completedAt: timestampSchema,
  status: z.enum(["unsafe_action_proposed", "attack_blocked"]),
  steps: z.array(agentTraceStepSchema).min(1),
  capabilityRequests: z.array(capabilityRequestSchema),
  decision: policyDecisionSchema.nullable(),
  receipt: threatReceiptSchema.nullable(),
});

export type TrustZone = z.infer<typeof trustZoneSchema>;
export type EventStage = z.infer<typeof eventStageSchema>;
export type Impact = z.infer<typeof impactSchema>;
export type EnforcementMode = z.infer<typeof enforcementModeSchema>;
export type DecisionOutcome = z.infer<typeof decisionOutcomeSchema>;
export type AttackClass = z.infer<typeof attackClassSchema>;
export type CapabilityClass = z.infer<typeof capabilityClassSchema>;
export type AgentFramework = z.infer<typeof agentFrameworkSchema>;
export type Adapter = z.infer<typeof adapterSchema>;
export type DadiengEvent = z.infer<typeof dadiengEventSchema>;
export type PolicyDecision = z.infer<typeof policyDecisionSchema>;
export type ThreatReceipt = z.infer<typeof threatReceiptSchema>;
export type PrivateThreatEvidence = z.infer<typeof privateThreatEvidenceSchema>;
export type EncryptedThreatEvidence = z.infer<typeof encryptedThreatEvidenceSchema>;
export type DefenseManifest = z.infer<typeof defenseManifestSchema>;
export type DefenseArtifact = z.infer<typeof defenseArtifactSchema>;
export type DefenseSbom = z.infer<typeof defenseSbomSchema>;
export type DefenseTestSuite = z.infer<typeof defenseTestSuiteSchema>;
export type ReplayReport = z.infer<typeof replayReportSchema>;
export type ValidatorAttestation = z.infer<typeof validatorAttestationSchema>;
export type StableManifest = z.infer<typeof stableManifestSchema>;
export type CapabilityRequest = z.infer<typeof capabilityRequestSchema>;
export type AgentTraceStep = z.infer<typeof agentTraceStepSchema>;
export type AgentRunTrace = z.infer<typeof agentRunTraceSchema>;

export interface DefenseRule {
  defenseId: string;
  version: string;
  evaluate(event: DadiengEvent): Omit<PolicyDecision, "schemaVersion" | "decisionId" | "eventId" | "evaluatedAt"> | null;
}
