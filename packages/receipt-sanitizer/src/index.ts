import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
} from "node:crypto";
import {
  DADIENG_ENCRYPTED_EVIDENCE_SCHEMA_VERSION,
  DADIENG_PRIVATE_EVIDENCE_SCHEMA_VERSION,
  DADIENG_RECEIPT_SCHEMA_VERSION,
  DADIENG_TAXONOMY_SCHEMA_VERSION,
  encryptedThreatEvidenceSchema,
  privateThreatEvidenceSchema,
  threatReceiptSchema,
  type Adapter,
  type AgentFramework,
  type AttackClass,
  type CapabilityClass,
  type DadiengEvent,
  type EncryptedThreatEvidence,
  type PolicyDecision,
  type PrivateThreatEvidence,
  type ThreatReceipt,
} from "@dadieng/schemas";

const ATTACK_CLASS_BY_REASON: Record<string, AttackClass> = {
  UNTRUSTED_TOOL_INSTRUCTION: "tool_poisoning",
  SECRET_ACCESS_REQUEST: "data_exfiltration",
  EXFILTRATION_REQUEST: "data_exfiltration",
};

const SECRET_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/i,
  /\bsk-[A-Za-z0-9_-]{8,}/i,
  /\bAKIA[A-Z0-9]{16}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

export interface EvidenceEncryptionOptions {
  key: Uint8Array;
  keyId: string;
  createIv?: (() => Uint8Array) | undefined;
  encryptedUri?: ((receiptId: string) => string) | undefined;
}

export interface ThreatReceiptPipelineOptions {
  encryption: EvidenceEncryptionOptions;
  createId?: (() => string) | undefined;
  publishReporterAgentId?: boolean | undefined;
  erc8004Id?: string | undefined;
  replayFixtureUri?: string | undefined;
  sanitizationConfidence?: number | undefined;
}

export interface ThreatReceiptPipelineResult {
  receipt: ThreatReceipt;
  encryptedEvidence: EncryptedThreatEvidence;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .map(([key, child]) => [key, canonicalize(child)]),
    );
  }
  return value;
}

export function canonicalEvidenceJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function evidenceHash(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalEvidenceJson(value)).digest("hex")}`;
}

function classify(decision: PolicyDecision): AttackClass {
  for (const reason of decision.reasonCodes) {
    const attackClass = ATTACK_CLASS_BY_REASON[reason];
    if (attackClass) return attackClass;
  }
  return "prompt_injection";
}

function classifyCapabilities(name: string | undefined): CapabilityClass[] {
  if (!name) return ["unknown"];

  const capabilities = new Set<CapabilityClass>();
  if (/secret|credential|private[_ .-]?key|seed[_ .-]?phrase/i.test(name)) capabilities.add("secrets.read");
  if (/network[._ -]?send|http|upload|exfiltrat/i.test(name)) capabilities.add("network.send");
  if (/filesystem[._ -]?write|file[._ -]?write/i.test(name)) capabilities.add("filesystem.write");
  if (/filesystem[._ -]?read|file[._ -]?read/i.test(name)) capabilities.add("filesystem.read");
  if (/shell|process[._ -]?execute|command[._ -]?execute/i.test(name)) capabilities.add("process.execute");
  if (/payment|transfer/i.test(name)) capabilities.add("payment.transfer");
  if (/email[._ -]?send|message[._ -]?send/i.test(name)) capabilities.add("communications.send");
  if (/data[._ -]?write|database[._ -]?write/i.test(name)) capabilities.add("data.write");
  if (/data[._ -]?read|database[._ -]?read|fetch|search/i.test(name)) capabilities.add("data.read");
  if (/content[._ -]?inspect/i.test(name)) capabilities.add("content.inspect");
  return capabilities.size > 0 ? [...capabilities].sort() : ["unknown"];
}

function classifyFramework(framework: string): AgentFramework {
  if (/vercel/i.test(framework)) return "vercel-ai";
  if (/langchain/i.test(framework)) return "langchain";
  if (/mcp/i.test(framework)) return "mcp";
  return framework.trim() ? "custom" : "unknown";
}

function classifyAdapter(event: DadiengEvent): Adapter {
  const combined = `${event.source.type} ${event.agent.framework}`;
  if (/mcp/i.test(combined)) return "mcp";
  if (/vercel/i.test(combined)) return "vercel-ai";
  if (/langchain/i.test(combined)) return "langchain";
  return combined.trim() ? "custom" : "unknown";
}

function encryptionAad(receiptId: string, keyId: string): Buffer {
  return Buffer.from(canonicalEvidenceJson({
    schemaVersion: DADIENG_ENCRYPTED_EVIDENCE_SCHEMA_VERSION,
    receiptId,
    keyId,
  }));
}

function validateEncryption(options: EvidenceEncryptionOptions): void {
  if (options.key.byteLength !== 32) throw new Error("Threat evidence encryption requires a 32-byte key");
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(options.keyId)) throw new Error("Threat evidence keyId is invalid");
}

export function encryptThreatEvidence(
  evidence: PrivateThreatEvidence,
  options: EvidenceEncryptionOptions,
): EncryptedThreatEvidence {
  validateEncryption(options);
  const iv = Buffer.from(options.createIv?.() ?? randomBytes(12));
  if (iv.byteLength !== 12) throw new Error("Threat evidence AES-GCM IV must be 12 bytes");

  const cipher = createCipheriv("aes-256-gcm", options.key, iv);
  cipher.setAAD(encryptionAad(evidence.receiptId, options.keyId));
  const ciphertext = Buffer.concat([
    cipher.update(canonicalEvidenceJson(evidence), "utf8"),
    cipher.final(),
  ]);

  return encryptedThreatEvidenceSchema.parse({
    schemaVersion: DADIENG_ENCRYPTED_EVIDENCE_SCHEMA_VERSION,
    receiptId: evidence.receiptId,
    algorithm: "aes-256-gcm-v1",
    keyId: options.keyId,
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
  });
}

export function decryptThreatEvidence(
  encryptedInput: EncryptedThreatEvidence,
  key: Uint8Array,
): PrivateThreatEvidence {
  const encrypted = encryptedThreatEvidenceSchema.parse(encryptedInput);
  if (key.byteLength !== 32) throw new Error("Threat evidence decryption requires a 32-byte key");

  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(encrypted.iv, "base64"));
  decipher.setAAD(encryptionAad(encrypted.receiptId, encrypted.keyId));
  decipher.setAuthTag(Buffer.from(encrypted.authTag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
  const evidence = privateThreatEvidenceSchema.parse(JSON.parse(plaintext));
  if (evidence.receiptId !== encrypted.receiptId) throw new Error("Encrypted evidence receipt ID mismatch");
  return evidence;
}

export function assertPublicReceiptSafe(receiptInput: ThreatReceipt, forbiddenValues: string[] = []): ThreatReceipt {
  const receipt = threatReceiptSchema.parse(receiptInput);
  const serialized = canonicalEvidenceJson(receipt);

  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(serialized)) throw new Error("Public Threat Receipt contains a credential-like value");
  }
  for (const value of forbiddenValues) {
    if (value.length >= 8 && serialized.includes(value)) {
      throw new Error("Public Threat Receipt contains private evidence content");
    }
  }
  return receipt;
}

export function verifyEvidenceCommitment(
  receiptInput: ThreatReceipt,
  encryptedInput: EncryptedThreatEvidence,
): boolean {
  const receipt = threatReceiptSchema.parse(receiptInput);
  const encrypted = encryptedThreatEvidenceSchema.parse(encryptedInput);
  return receipt.receiptId === encrypted.receiptId && receipt.evidence.hash === evidenceHash(encrypted);
}

export function createThreatReceiptPipeline(
  event: DadiengEvent,
  decision: PolicyDecision,
  options: ThreatReceiptPipelineOptions,
): ThreatReceiptPipelineResult {
  if (decision.outcome !== "BLOCK" && decision.outcome !== "OBSERVE") {
    throw new Error(`Cannot create a threat receipt for ${decision.outcome}`);
  }

  const receiptId = (options.createId ?? randomUUID)();
  const sourceFingerprint = event.contentReferences[0]?.fingerprint ?? evidenceHash(event.source.type);
  const attackClass = classify(decision);
  const capabilities = classifyCapabilities(event.capability?.name);
  const confidence = options.sanitizationConfidence ?? 1;
  const privateEvidence = privateThreatEvidenceSchema.parse({
    schemaVersion: DADIENG_PRIVATE_EVIDENCE_SCHEMA_VERSION,
    receiptId,
    capturedAt: event.timestamp,
    event,
    decision,
  });
  const encryptedEvidence = encryptThreatEvidence(privateEvidence, options.encryption);
  const encryptedUri = options.encryption.encryptedUri?.(receiptId)
    ?? `local://dadieng/evidence/${evidenceHash(receiptId).slice("sha256:".length)}`;
  const summary = `${decision.outcome === "BLOCK" ? "Blocked" : "Observed"} ${attackClass.replaceAll("_", " ")} affecting ${capabilities.join(", ")}.`;

  const receipt = threatReceiptSchema.parse({
    schemaVersion: DADIENG_RECEIPT_SCHEMA_VERSION,
    receiptId,
    observedAt: event.timestamp,
    reporter: {
      ...(options.publishReporterAgentId ? { agentId: event.agent.agentId } : {}),
      agentFingerprint: evidenceHash(event.agent.agentId),
      ...(options.erc8004Id ? { erc8004Id: options.erc8004Id } : {}),
      sdkVersion: event.agent.sdkVersion,
    },
    classification: {
      taxonomyVersion: DADIENG_TAXONOMY_SCHEMA_VERSION,
      attackClass,
      severity: event.capability?.impact ?? "medium",
      confidence: 0.98,
    },
    surface: {
      framework: classifyFramework(event.agent.framework),
      adapter: classifyAdapter(event),
      capabilities,
    },
    source: { trustZone: event.source.trustZone, fingerprint: sourceFingerprint },
    sanitized: {
      summary,
      ...(options.replayFixtureUri ? { replayFixtureUri: options.replayFixtureUri } : {}),
    },
    evidence: {
      hash: evidenceHash(encryptedEvidence),
      encryptedUri,
      encryption: "aes-256-gcm-v1",
      keyId: options.encryption.keyId,
    },
    deduplicationKey: evidenceHash({
      taxonomyVersion: DADIENG_TAXONOMY_SCHEMA_VERSION,
      attackClass,
      capabilities,
      sourceFingerprint,
      reasonCodes: [...decision.reasonCodes].sort(),
    }),
    privacy: {
      containsRawPrompt: false,
      containsCredentials: false,
      containsPersonalData: false,
      redactionPolicy: "dadieng.strict-redaction.v1",
      sanitizationConfidence: confidence,
      manualReviewRequired: event.capability?.impact === "high" || event.capability?.impact === "critical",
    },
  });

  return {
    receipt: assertPublicReceiptSafe(receipt, [event.content]),
    encryptedEvidence,
  };
}

export function createThreatReceipt(
  event: DadiengEvent,
  decision: PolicyDecision,
  createId: () => string = randomUUID,
): ThreatReceipt {
  return createThreatReceiptPipeline(event, decision, {
    createId,
    encryption: {
      key: randomBytes(32),
      keyId: "ephemeral-v1",
    },
  }).receipt;
}
