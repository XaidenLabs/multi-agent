import { randomUUID } from "node:crypto";
import type { QueryResult, QueryResultRow } from "pg";
import type {
  ChainOperationRecord,
  ChainOperationRepository,
  ChainOperationRequest,
  ClaimedChainOperation,
} from "@dadieng/contracts-client";
import type { DefenseBundle } from "@dadieng/defense-module";
import {
  replayEnvironmentSchema,
  replayReportSchema,
  stableManifestSchema,
  threatReceiptSchema,
  validatorAttestationSchema,
  type ReplayReport,
  type ThreatReceipt,
  type StableManifest,
  type ValidatorAttestation,
} from "@dadieng/schemas";
import { createReplayRequestSchema, defenseBundleSchema, type CreateReplayRequest } from "./contracts.js";

export interface EvidenceObjectReference {
  uri: string;
  hash: string;
  sizeBytes: number;
  storedAt: string;
}

export interface ReceiptRecord {
  tenantId: string;
  receipt: ThreatReceipt;
  evidenceHash: string;
  evidenceObject?: EvidenceObjectReference;
  evidenceDeletedAt?: string;
  createdAt: string;
}

export interface DefenseRecord {
  defenseId: string;
  name: string;
  authorAgentId: string;
  createdAt: string;
}

export interface DefenseVersionRecord {
  defenseVersionId: string;
  defenseId: string;
  bundle: DefenseBundle;
  status: "candidate";
  createdAt: string;
}

export interface ReplayJobRecord {
  replayId: string;
  tenantId: string;
  request: CreateReplayRequest;
  status: "queued" | "running" | "completed" | "failed";
  report?: ReplayReport;
  errorCode?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ValidationJobRecord {
  jobId: string;
  tenantId: string;
  replayId: string;
  defenseVersionId: string;
  versionKey: `0x${string}`;
  chainId: number;
  registryAddress: `0x${string}`;
  validationAddress: `0x${string}`;
  bundle: DefenseBundle;
  environment: ReplayReport["environment"];
  thresholds?: CreateReplayRequest["thresholds"];
  canonicalReportHash: string;
  status: "open" | "claimed" | "submitted";
  claimedBy?: string;
  validatorAgentId?: string;
  validatorAddress?: `0x${string}`;
  claimExpiresAt?: string;
  report?: ReplayReport;
  attestation?: ValidatorAttestation;
  transactionHash?: `0x${string}`;
  createdAt: string;
  updatedAt: string;
}

export interface StableManifestRecord {
  manifestHash: string;
  manifest: StableManifest;
  createdAt: string;
}

export interface StoredHttpResponse {
  requestHash: string;
  status: number;
  body: unknown;
  headers: Record<string, string>;
}

export type IdempotencyClaim =
  | { outcome: "claimed"; token: string }
  | { outcome: "replay"; response: StoredHttpResponse }
  | { outcome: "conflict" }
  | { outcome: "in-progress" };

export interface ReceiptSaveResult {
  created: boolean;
  record: ReceiptRecord;
}

export interface ControlPlaneRepository extends ChainOperationRepository {
  healthCheck(): Promise<void>;
  getReceipt(receiptId: string): Promise<ReceiptRecord | undefined>;
  getReceiptForTenant(tenantId: string, receiptId: string): Promise<ReceiptRecord | undefined>;
  saveReceipt(record: ReceiptRecord): Promise<ReceiptSaveResult>;
  saveDefense(record: DefenseRecord): Promise<boolean>;
  getDefense(defenseId: string): Promise<DefenseRecord | undefined>;
  saveDefenseVersion(record: DefenseVersionRecord): Promise<boolean>;
  getDefenseVersion(defenseVersionId: string): Promise<DefenseVersionRecord | undefined>;
  listDefenseVersions(): Promise<DefenseVersionRecord[]>;
  saveReplay(record: ReplayJobRecord): Promise<void>;
  getReplay(replayId: string): Promise<ReplayJobRecord | undefined>;
  claimNextReplay(updatedAt: string): Promise<ReplayJobRecord | undefined>;
  saveValidationJob(record: ValidationJobRecord): Promise<boolean>;
  getValidationJob(jobId: string): Promise<ValidationJobRecord | undefined>;
  getValidationJobByAttestationId(attestationId: string): Promise<ValidationJobRecord | undefined>;
  listValidationJobs(tenantId: string, subject: string, now: string): Promise<ValidationJobRecord[]>;
  claimValidationJob(
    jobId: string,
    tenantId: string,
    subject: string,
    validatorAgentId: string,
    validatorAddress: `0x${string}`,
    now: string,
    claimExpiresAt: string,
  ): Promise<ValidationJobRecord | undefined>;
  completeValidationJob(record: ValidationJobRecord, subject: string): Promise<boolean>;
  getLatestStableManifest(channel: string): Promise<StableManifestRecord | undefined>;
  saveStableManifest(record: StableManifestRecord): Promise<boolean>;
  claimIdempotency(key: string, requestHash: string, createdAt: string): Promise<IdempotencyClaim>;
  completeIdempotency(key: string, token: string, response: StoredHttpResponse, completedAt: string): Promise<void>;
  abandonIdempotency(key: string, token: string): Promise<void>;
  listExpiredEvidence(cutoff: string, limit: number): Promise<ReceiptRecord[]>;
  markEvidenceDeleted(receiptId: string, deletedAt: string): Promise<void>;
}

function copy<T>(value: T): T {
  return structuredClone(value);
}

export class InMemoryControlPlaneRepository implements ControlPlaneRepository {
  private readonly receipts = new Map<string, ReceiptRecord>();
  private readonly receiptDeduplication = new Map<string, string>();
  private readonly defenses = new Map<string, DefenseRecord>();
  private readonly versions = new Map<string, DefenseVersionRecord>();
  private readonly replays = new Map<string, ReplayJobRecord>();
  private readonly validationJobs = new Map<string, ValidationJobRecord>();
  private readonly stableManifests = new Map<string, StableManifestRecord>();
  private readonly idempotency = new Map<string, { requestHash: string; token: string; expiresAt: string; response?: StoredHttpResponse }>();
  private readonly chainOperations = new Map<string, ChainOperationRecord>();
  private readonly chainOperationDeduplication = new Map<string, string>();
  private readonly chainOperationClaims = new Map<string, { token: string; expiresAt: string }>();

  async healthCheck(): Promise<void> {}

  async getReceipt(receiptId: string) { const value = this.receipts.get(receiptId); return value ? copy(value) : undefined; }
  async getReceiptForTenant(tenantId: string, receiptId: string) {
    const value = this.receipts.get(receiptId);
    return value?.tenantId === tenantId ? copy(value) : undefined;
  }
  async saveReceipt(record: ReceiptRecord): Promise<ReceiptSaveResult> {
    const deduplicationKey = `${record.tenantId}:${record.receipt.deduplicationKey}`;
    const duplicateId = this.receiptDeduplication.get(deduplicationKey);
    if (duplicateId) return { created: false, record: copy(this.receipts.get(duplicateId)!) };
    if (this.receipts.has(record.receipt.receiptId)) throw new RepositoryConflictError("receipt-id");
    this.receipts.set(record.receipt.receiptId, copy(record));
    this.receiptDeduplication.set(deduplicationKey, record.receipt.receiptId);
    return { created: true, record: copy(record) };
  }
  async saveDefense(record: DefenseRecord) {
    if (this.defenses.has(record.defenseId)) return false;
    this.defenses.set(record.defenseId, copy(record));
    return true;
  }
  async getDefense(defenseId: string) { const value = this.defenses.get(defenseId); return value ? copy(value) : undefined; }
  async saveDefenseVersion(record: DefenseVersionRecord) {
    if (this.versions.has(record.defenseVersionId)) return false;
    this.versions.set(record.defenseVersionId, copy(record));
    return true;
  }
  async getDefenseVersion(defenseVersionId: string) { const value = this.versions.get(defenseVersionId); return value ? copy(value) : undefined; }
  async listDefenseVersions() { return [...this.versions.values()].map(copy); }
  async saveReplay(record: ReplayJobRecord) { this.replays.set(record.replayId, copy(record)); }
  async getReplay(replayId: string) { const value = this.replays.get(replayId); return value ? copy(value) : undefined; }
  async claimNextReplay(updatedAt: string) {
    const value = [...this.replays.values()].find((record) => record.status === "queued");
    if (!value) return undefined;
    value.status = "running";
    value.updatedAt = updatedAt;
    this.replays.set(value.replayId, copy(value));
    return copy(value);
  }
  async saveValidationJob(record: ValidationJobRecord) {
    if ([...this.validationJobs.values()].some((job) => job.replayId === record.replayId)) return false;
    this.validationJobs.set(record.jobId, copy(record));
    return true;
  }
  async getValidationJob(jobId: string) {
    const value = this.validationJobs.get(jobId);
    return value ? copy(value) : undefined;
  }
  async getValidationJobByAttestationId(attestationId: string) {
    const value = [...this.validationJobs.values()].find((job) => job.attestation?.attestationId === attestationId);
    return value ? copy(value) : undefined;
  }
  async listValidationJobs(tenantId: string, subject: string, now: string) {
    return [...this.validationJobs.values()]
      .filter((job) => job.tenantId === tenantId && (
        job.status === "open" || (job.status === "claimed" && (job.claimedBy === subject || job.claimExpiresAt! <= now))
      ))
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.jobId.localeCompare(right.jobId))
      .map(copy);
  }
  async claimValidationJob(
    jobId: string,
    tenantId: string,
    subject: string,
    validatorAgentId: string,
    validatorAddress: `0x${string}`,
    now: string,
    claimExpiresAt: string,
  ) {
    const job = this.validationJobs.get(jobId);
    if (!job || job.tenantId !== tenantId || job.status === "submitted") return undefined;
    if (job.status === "claimed" && job.claimedBy !== subject && job.claimExpiresAt! > now) return undefined;
    job.status = "claimed";
    job.claimedBy = subject;
    job.validatorAgentId = validatorAgentId;
    job.validatorAddress = validatorAddress;
    job.claimExpiresAt = claimExpiresAt;
    job.updatedAt = now;
    this.validationJobs.set(jobId, copy(job));
    return copy(job);
  }
  async completeValidationJob(record: ValidationJobRecord, subject: string) {
    const existing = this.validationJobs.get(record.jobId);
    if (!existing || existing.status !== "claimed" || existing.claimedBy !== subject) return false;
    this.validationJobs.set(record.jobId, copy(record));
    return true;
  }
  async getLatestStableManifest(channel: string) {
    return [...this.stableManifests.values()]
      .filter((record) => record.manifest.channel === channel)
      .sort((left, right) => right.manifest.generatedAt.localeCompare(left.manifest.generatedAt)
        || right.manifestHash.localeCompare(left.manifestHash))[0];
  }
  async saveStableManifest(record: StableManifestRecord) {
    if (this.stableManifests.has(record.manifestHash)) return false;
    if ([...this.stableManifests.values()].some((item) =>
      item.manifest.channel === record.manifest.channel
      && item.manifest.previousManifestHash === record.manifest.previousManifestHash)) return false;
    this.stableManifests.set(record.manifestHash, copy(record));
    return true;
  }
  async claimIdempotency(key: string, requestHash: string, createdAt: string): Promise<IdempotencyClaim> {
    const existing = this.idempotency.get(key);
    if (!existing) {
      const token = randomUUID();
      const expiresAt = new Date(new Date(createdAt).getTime() + 300_000).toISOString();
      this.idempotency.set(key, { requestHash, token, expiresAt });
      return { outcome: "claimed", token };
    }
    if (existing.requestHash !== requestHash) return { outcome: "conflict" };
    if (!existing.response && existing.expiresAt <= createdAt) {
      const token = randomUUID();
      const expiresAt = new Date(new Date(createdAt).getTime() + 300_000).toISOString();
      this.idempotency.set(key, { requestHash, token, expiresAt });
      return { outcome: "claimed", token };
    }
    return existing.response ? { outcome: "replay", response: copy(existing.response) } : { outcome: "in-progress" };
  }
  async completeIdempotency(key: string, token: string, response: StoredHttpResponse) {
    const existing = this.idempotency.get(key);
    if (!existing || existing.token !== token) throw new Error("Idempotency claim is missing");
    existing.response = copy(response);
  }
  async abandonIdempotency(key: string, token: string) {
    const existing = this.idempotency.get(key);
    if (existing?.token === token && !existing.response) this.idempotency.delete(key);
  }
  async listExpiredEvidence(cutoff: string, limit: number) {
    return [...this.receipts.values()]
      .filter((record) => record.evidenceObject && record.evidenceObject.storedAt < cutoff)
      .sort((left, right) => left.evidenceObject!.storedAt.localeCompare(right.evidenceObject!.storedAt))
      .slice(0, limit)
      .map(copy);
  }
  async markEvidenceDeleted(receiptId: string, deletedAt: string) {
    const record = this.receipts.get(receiptId);
    if (!record) return;
    delete record.evidenceObject;
    record.evidenceDeletedAt = deletedAt;
  }

  async enqueueChainOperation(record: ChainOperationRecord) {
    const existingId = this.chainOperationDeduplication.get(record.deduplicationKey);
    if (existingId) return { created: false, operation: copy(this.chainOperations.get(existingId)!) };
    this.chainOperations.set(record.operationId, copy(record));
    this.chainOperationDeduplication.set(record.deduplicationKey, record.operationId);
    return { created: true, operation: copy(record) };
  }

  async getChainOperation(operationId: string) {
    const operation = this.chainOperations.get(operationId);
    return operation ? copy(operation) : undefined;
  }

  async claimNextChainOperation(now: string, claimExpiresAt: string): Promise<ClaimedChainOperation | undefined> {
    if ([...this.chainOperationClaims.values()].some((claim) => claim.expiresAt > now)) return undefined;
    const operation = [...this.chainOperations.values()]
      .filter((candidate) => candidate.status !== "confirmed" && candidate.status !== "failed" && candidate.nextAttemptAt <= now)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.operationId.localeCompare(right.operationId))
      .find((candidate) => {
        const claim = this.chainOperationClaims.get(candidate.operationId);
        return !claim || claim.expiresAt <= now;
      });
    if (!operation) return undefined;
    const claimToken = randomUUID();
    this.chainOperationClaims.set(operation.operationId, { token: claimToken, expiresAt: claimExpiresAt });
    return { operation: copy(operation), claimToken };
  }

  async updateClaimedChainOperation(operation: ChainOperationRecord, claimToken: string) {
    const claim = this.chainOperationClaims.get(operation.operationId);
    if (!claim || claim.token !== claimToken) throw new Error("Chain operation claim update failed");
    this.chainOperations.set(operation.operationId, copy(operation));
    this.chainOperationClaims.delete(operation.operationId);
  }
}

export class RepositoryConflictError extends Error {
  constructor(readonly conflict: "receipt-id") {
    super(`Repository conflict: ${conflict}`);
  }
}

export interface SqlClient {
  query<R extends QueryResultRow = any>(text: string, values?: readonly unknown[]): Promise<QueryResult<R>>;
}

interface ReceiptRow extends QueryResultRow {
  receipt_id: string; tenant_id: string; public_receipt: unknown; evidence_hash: string;
  evidence_object_uri: string | null; evidence_size_bytes: number | null;
  evidence_stored_at: Date | string | null; evidence_deleted_at: Date | string | null; created_at: Date | string;
}
interface DefenseRow extends QueryResultRow {
  defense_id: string; name: string; author_agent_id: string; created_at: Date | string;
}
interface VersionRow extends QueryResultRow {
  defense_version_id: string; defense_id: string; bundle: unknown; status: "candidate"; created_at: Date | string;
}
interface ReplayRow extends QueryResultRow {
  replay_id: string; tenant_id: string; request: unknown; status: ReplayJobRecord["status"];
  report: unknown | null; error_code: string | null; created_at: Date | string; updated_at: Date | string;
}
interface ValidationJobRow extends QueryResultRow {
  job_id: string; tenant_id: string; replay_id: string; defense_version_id: string; version_key: string;
  chain_id: number; registry_address: string; validation_address: string; bundle: unknown; environment: unknown;
  thresholds: unknown | null; canonical_report_hash: string; status: ValidationJobRecord["status"]; claimed_by: string | null;
  validator_agent_id: string | null; validator_address: string | null; claim_expires_at: Date | string | null;
  report: unknown | null; attestation: unknown | null; transaction_hash: string | null;
  created_at: Date | string; updated_at: Date | string;
}
interface StableManifestRow extends QueryResultRow {
  manifest_hash: string; channel: string; previous_manifest_hash: string | null;
  manifest: unknown; generated_at: Date | string; expires_at: Date | string; created_at: Date | string;
}
interface IdempotencyRow extends QueryResultRow {
  request_hash: string; claim_token: string; claim_expires_at: Date | string;
  response_status: number | null; response_body: unknown | null; response_headers: unknown | null;
}
interface ChainOperationRow extends QueryResultRow {
  operation_id: string; deduplication_key: string; tenant_id: string; operation_kind: ChainOperationRequest["kind"];
  payload: ChainOperationRequest; status: ChainOperationRecord["status"]; attempts: number;
  next_attempt_at: Date | string; prepared_transaction_hash: string | null; serialized_transaction: string | null;
  transaction_hash: string | null; block_number: string | null; confirmations: number | null; error_code: string | null;
  created_at: Date | string; updated_at: Date | string; claim_token: string | null; claim_expires_at: Date | string | null;
}

function timestamp(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function receiptFromRow(row: ReceiptRow): ReceiptRecord {
  return {
    tenantId: row.tenant_id,
    receipt: threatReceiptSchema.parse(row.public_receipt),
    evidenceHash: row.evidence_hash,
    ...(row.evidence_object_uri && row.evidence_size_bytes !== null && row.evidence_stored_at ? {
      evidenceObject: {
        uri: row.evidence_object_uri,
        hash: row.evidence_hash,
        sizeBytes: row.evidence_size_bytes,
        storedAt: timestamp(row.evidence_stored_at),
      },
    } : {}),
    ...(row.evidence_deleted_at ? { evidenceDeletedAt: timestamp(row.evidence_deleted_at) } : {}),
    createdAt: timestamp(row.created_at),
  };
}

function defenseFromRow(row: DefenseRow): DefenseRecord {
  return { defenseId: row.defense_id, name: row.name, authorAgentId: row.author_agent_id, createdAt: timestamp(row.created_at) };
}

function versionFromRow(row: VersionRow): DefenseVersionRecord {
  return {
    defenseVersionId: row.defense_version_id,
    defenseId: row.defense_id,
    bundle: defenseBundleSchema.parse(row.bundle),
    status: row.status,
    createdAt: timestamp(row.created_at),
  };
}

function replayFromRow(row: ReplayRow): ReplayJobRecord {
  return {
    replayId: row.replay_id,
    tenantId: row.tenant_id,
    request: createReplayRequestSchema.parse(row.request),
    status: row.status,
    ...(row.report ? { report: replayReportSchema.parse(row.report) } : {}),
    ...(row.error_code ? { errorCode: row.error_code } : {}),
    createdAt: timestamp(row.created_at),
    updatedAt: timestamp(row.updated_at),
  };
}

function validationJobFromRow(row: ValidationJobRow): ValidationJobRecord {
  return {
    jobId: row.job_id,
    tenantId: row.tenant_id,
    replayId: row.replay_id,
    defenseVersionId: row.defense_version_id,
    versionKey: row.version_key as `0x${string}`,
    chainId: row.chain_id,
    registryAddress: row.registry_address as `0x${string}`,
    validationAddress: row.validation_address as `0x${string}`,
    bundle: defenseBundleSchema.parse(row.bundle),
    environment: replayEnvironmentSchema.parse(row.environment),
    ...(row.thresholds ? { thresholds: createReplayRequestSchema.shape.thresholds.parse(row.thresholds) } : {}),
    canonicalReportHash: row.canonical_report_hash,
    status: row.status,
    ...(row.claimed_by ? { claimedBy: row.claimed_by } : {}),
    ...(row.validator_agent_id ? { validatorAgentId: row.validator_agent_id } : {}),
    ...(row.validator_address ? { validatorAddress: row.validator_address as `0x${string}` } : {}),
    ...(row.claim_expires_at ? { claimExpiresAt: timestamp(row.claim_expires_at) } : {}),
    ...(row.report ? { report: replayReportSchema.parse(row.report) } : {}),
    ...(row.attestation ? { attestation: validatorAttestationSchema.parse(row.attestation) } : {}),
    ...(row.transaction_hash ? { transactionHash: row.transaction_hash as `0x${string}` } : {}),
    createdAt: timestamp(row.created_at),
    updatedAt: timestamp(row.updated_at),
  };
}

function stableManifestFromRow(row: StableManifestRow): StableManifestRecord {
  return {
    manifestHash: row.manifest_hash,
    manifest: stableManifestSchema.parse(row.manifest),
    createdAt: timestamp(row.created_at),
  };
}

function chainOperationFromRow(row: ChainOperationRow): ChainOperationRecord {
  return {
    operationId: row.operation_id,
    deduplicationKey: row.deduplication_key,
    tenantId: row.tenant_id,
    request: row.payload,
    status: row.status,
    attempts: row.attempts,
    nextAttemptAt: timestamp(row.next_attempt_at),
    ...(row.prepared_transaction_hash ? { preparedTransactionHash: row.prepared_transaction_hash as `0x${string}` } : {}),
    ...(row.serialized_transaction ? { serializedTransaction: row.serialized_transaction as `0x${string}` } : {}),
    ...(row.transaction_hash ? { transactionHash: row.transaction_hash as `0x${string}` } : {}),
    ...(row.block_number ? { blockNumber: row.block_number } : {}),
    ...(row.confirmations !== null ? { confirmations: row.confirmations } : {}),
    ...(row.error_code ? { errorCode: row.error_code } : {}),
    createdAt: timestamp(row.created_at),
    updatedAt: timestamp(row.updated_at),
  };
}

export class PostgresControlPlaneRepository implements ControlPlaneRepository {
  constructor(private readonly database: SqlClient) {}

  async healthCheck(): Promise<void> {
    await this.database.query("SELECT 1");
  }

  async getReceipt(receiptId: string) {
    const result = await this.database.query<ReceiptRow>("SELECT * FROM threat_receipts WHERE receipt_id = $1", [receiptId]);
    return result.rows[0] ? receiptFromRow(result.rows[0]) : undefined;
  }

  async getReceiptForTenant(tenantId: string, receiptId: string) {
    const result = await this.database.query<ReceiptRow>(
      "SELECT * FROM threat_receipts WHERE tenant_id = $1 AND receipt_id = $2",
      [tenantId, receiptId],
    );
    return result.rows[0] ? receiptFromRow(result.rows[0]) : undefined;
  }

  async saveReceipt(record: ReceiptRecord): Promise<ReceiptSaveResult> {
    if (!record.evidenceObject) throw new Error("A persisted receipt requires an evidence object reference");
    try {
      const existing = await this.database.query<ReceiptRow>(
        "SELECT * FROM threat_receipts WHERE tenant_id = $1 AND deduplication_key = $2",
        [record.tenantId, record.receipt.deduplicationKey],
      );
      if (existing.rows[0]) return { created: false, record: receiptFromRow(existing.rows[0]) };
      const result = await this.database.query<ReceiptRow>(`
        INSERT INTO threat_receipts
          (receipt_id, tenant_id, deduplication_key, public_receipt, evidence_object_uri, evidence_hash,
           evidence_size_bytes, evidence_stored_at, created_at)
        VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9)
        ON CONFLICT (tenant_id, deduplication_key) DO NOTHING
        RETURNING *`, [
        record.receipt.receiptId, record.tenantId, record.receipt.deduplicationKey,
        JSON.stringify(record.receipt), record.evidenceObject.uri, record.evidenceHash,
        record.evidenceObject.sizeBytes, record.evidenceObject.storedAt, record.createdAt,
      ]);
      if (result.rows[0]) return { created: true, record: receiptFromRow(result.rows[0]) };
      const duplicate = await this.database.query<ReceiptRow>(
        "SELECT * FROM threat_receipts WHERE tenant_id = $1 AND deduplication_key = $2",
        [record.tenantId, record.receipt.deduplicationKey],
      );
      if (!duplicate.rows[0]) throw new Error("Receipt deduplication conflict could not be resolved");
      return { created: false, record: receiptFromRow(duplicate.rows[0]) };
    } catch (error) {
      if ((error as { code?: string }).code === "23505") throw new RepositoryConflictError("receipt-id");
      throw error;
    }
  }

  async saveDefense(record: DefenseRecord) {
    const result = await this.database.query(`
      INSERT INTO defenses (defense_id, name, author_agent_id, created_at) VALUES ($1, $2, $3, $4)
      ON CONFLICT (defense_id) DO NOTHING RETURNING defense_id`,
    [record.defenseId, record.name, record.authorAgentId, record.createdAt]);
    return result.rowCount === 1;
  }

  async getDefense(defenseId: string) {
    const result = await this.database.query<DefenseRow>("SELECT * FROM defenses WHERE defense_id = $1", [defenseId]);
    return result.rows[0] ? defenseFromRow(result.rows[0]) : undefined;
  }

  async saveDefenseVersion(record: DefenseVersionRecord) {
    const result = await this.database.query(`
      INSERT INTO defense_versions (defense_version_id, defense_id, bundle, status, created_at)
      VALUES ($1, $2, $3::jsonb, $4, $5)
      ON CONFLICT (defense_version_id) DO NOTHING RETURNING defense_version_id`,
    [record.defenseVersionId, record.defenseId, JSON.stringify(record.bundle), record.status, record.createdAt]);
    return result.rowCount === 1;
  }

  async getDefenseVersion(defenseVersionId: string) {
    const result = await this.database.query<VersionRow>("SELECT * FROM defense_versions WHERE defense_version_id = $1", [defenseVersionId]);
    return result.rows[0] ? versionFromRow(result.rows[0]) : undefined;
  }

  async listDefenseVersions() {
    const result = await this.database.query<VersionRow>("SELECT * FROM defense_versions ORDER BY defense_version_id");
    return result.rows.map(versionFromRow);
  }

  async saveReplay(record: ReplayJobRecord) {
    await this.database.query(`
      INSERT INTO replay_runs (replay_id, tenant_id, request, status, report, error_code, created_at, updated_at)
      VALUES ($1, $2, $3::jsonb, $4, $5::jsonb, $6, $7, $8)
      ON CONFLICT (replay_id) DO UPDATE SET status = EXCLUDED.status, report = EXCLUDED.report,
        error_code = EXCLUDED.error_code, updated_at = EXCLUDED.updated_at`, [
      record.replayId, record.tenantId, JSON.stringify(record.request), record.status,
      record.report ? JSON.stringify(record.report) : null, record.errorCode ?? null, record.createdAt, record.updatedAt,
    ]);
  }

  async getReplay(replayId: string) {
    const result = await this.database.query<ReplayRow>("SELECT * FROM replay_runs WHERE replay_id = $1", [replayId]);
    return result.rows[0] ? replayFromRow(result.rows[0]) : undefined;
  }

  async claimNextReplay(updatedAt: string) {
    const result = await this.database.query<ReplayRow>(`
      UPDATE replay_runs SET status = 'running', updated_at = $1
      WHERE replay_id = (SELECT replay_id FROM replay_runs WHERE status = 'queued' ORDER BY created_at, replay_id LIMIT 1)
        AND status = 'queued'
      RETURNING *`, [updatedAt]);
    return result.rows[0] ? replayFromRow(result.rows[0]) : undefined;
  }

  async saveValidationJob(record: ValidationJobRecord) {
    const result = await this.database.query(`
      INSERT INTO validation_jobs
        (job_id, tenant_id, replay_id, defense_version_id, version_key, chain_id, registry_address,
         validation_address, bundle, environment, thresholds, canonical_report_hash, status, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11::jsonb, $12, $13, $14, $15)
      ON CONFLICT (replay_id) DO NOTHING RETURNING job_id`, [
      record.jobId, record.tenantId, record.replayId, record.defenseVersionId, record.versionKey,
      record.chainId, record.registryAddress, record.validationAddress, JSON.stringify(record.bundle),
      JSON.stringify(record.environment), record.thresholds ? JSON.stringify(record.thresholds) : null,
      record.canonicalReportHash, record.status, record.createdAt, record.updatedAt,
    ]);
    return result.rowCount === 1;
  }

  async getValidationJob(jobId: string) {
    const result = await this.database.query<ValidationJobRow>("SELECT * FROM validation_jobs WHERE job_id = $1", [jobId]);
    return result.rows[0] ? validationJobFromRow(result.rows[0]) : undefined;
  }

  async getValidationJobByAttestationId(attestationId: string) {
    const result = await this.database.query<ValidationJobRow>(
      "SELECT * FROM validation_jobs WHERE status = 'submitted'",
    );
    const match = result.rows.map(validationJobFromRow).find((job) => job.attestation?.attestationId === attestationId);
    return match;
  }

  async listValidationJobs(tenantId: string, subject: string, now: string) {
    const result = await this.database.query<ValidationJobRow>(`
      SELECT * FROM validation_jobs WHERE tenant_id = $1 AND (
        status = 'open' OR (status = 'claimed' AND (claimed_by = $2 OR claim_expires_at <= $3))
      ) ORDER BY created_at, job_id`, [tenantId, subject, now]);
    return result.rows.map(validationJobFromRow);
  }

  async claimValidationJob(
    jobId: string,
    tenantId: string,
    subject: string,
    validatorAgentId: string,
    validatorAddress: `0x${string}`,
    now: string,
    claimExpiresAt: string,
  ) {
    const result = await this.database.query<ValidationJobRow>(`
      UPDATE validation_jobs SET status = 'claimed', claimed_by = $3, validator_agent_id = $4,
        validator_address = $5, claim_expires_at = $7, updated_at = $6
      WHERE job_id = $1 AND tenant_id = $2 AND status <> 'submitted'
        AND (status = 'open' OR claimed_by = $3 OR claim_expires_at <= $6)
      RETURNING *`, [jobId, tenantId, subject, validatorAgentId, validatorAddress, now, claimExpiresAt]);
    return result.rows[0] ? validationJobFromRow(result.rows[0]) : undefined;
  }

  async completeValidationJob(record: ValidationJobRecord, subject: string) {
    const result = await this.database.query(`
      UPDATE validation_jobs SET status = 'submitted', report = $3::jsonb, attestation = $4::jsonb,
        transaction_hash = $5, claim_expires_at = NULL, updated_at = $6
      WHERE job_id = $1 AND status = 'claimed' AND claimed_by = $2`, [
      record.jobId, subject, JSON.stringify(record.report), JSON.stringify(record.attestation),
      record.transactionHash, record.updatedAt,
    ]);
    return result.rowCount === 1;
  }

  async getLatestStableManifest(channel: string) {
    const result = await this.database.query<StableManifestRow>(`
      SELECT * FROM stable_manifests WHERE channel = $1 ORDER BY generated_at DESC, manifest_hash DESC LIMIT 1`,
    [channel]);
    return result.rows[0] ? stableManifestFromRow(result.rows[0]) : undefined;
  }

  async saveStableManifest(record: StableManifestRecord) {
    try {
      const result = await this.database.query(`
        INSERT INTO stable_manifests
          (manifest_hash, channel, previous_manifest_hash, lineage_parent, manifest, generated_at, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)
        ON CONFLICT (manifest_hash) DO NOTHING RETURNING manifest_hash`, [
        record.manifestHash, record.manifest.channel, record.manifest.previousManifestHash,
        record.manifest.previousManifestHash ?? "genesis", JSON.stringify(record.manifest),
        record.manifest.generatedAt, record.manifest.expiresAt, record.createdAt,
      ]);
      return result.rowCount === 1;
    } catch (error) {
      if ((error as { code?: string }).code === "23505") return false;
      throw error;
    }
  }

  async claimIdempotency(key: string, requestHash: string, createdAt: string): Promise<IdempotencyClaim> {
    const token = randomUUID();
    const expiresAt = new Date(new Date(createdAt).getTime() + 300_000).toISOString();
    const inserted = await this.database.query(`
      INSERT INTO idempotency_keys (storage_key, request_hash, claim_token, claim_expires_at, created_at)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (storage_key) DO NOTHING RETURNING storage_key`, [key, requestHash, token, expiresAt, createdAt]);
    const result = await this.database.query<IdempotencyRow>("SELECT * FROM idempotency_keys WHERE storage_key = $1", [key]);
    const existing = result.rows[0];
    if (!existing) throw new Error("Idempotency claim could not be resolved");
    if (existing.claim_token === token && inserted.rowCount === 1) return { outcome: "claimed", token };
    if (existing.request_hash !== requestHash) return { outcome: "conflict" };
    if (existing.response_status === null) {
      if (timestamp(existing.claim_expires_at) <= createdAt) {
        const reclaimed = await this.database.query<IdempotencyRow>(`
          UPDATE idempotency_keys SET request_hash = $2, claim_token = $3, claim_expires_at = $4, created_at = $5
          WHERE storage_key = $1 AND response_status IS NULL AND claim_expires_at <= $5 RETURNING *`,
        [key, requestHash, token, expiresAt, createdAt]);
        if (reclaimed.rows[0]?.claim_token === token) return { outcome: "claimed", token };
      }
      return { outcome: "in-progress" };
    }
    const headers = existing.response_headers;
    if (!headers || typeof headers !== "object" || Array.isArray(headers)) throw new Error("Invalid stored response headers");
    return {
      outcome: "replay",
      response: {
        requestHash: existing.request_hash,
        status: existing.response_status,
        body: existing.response_body,
        headers: headers as Record<string, string>,
      },
    };
  }

  async completeIdempotency(key: string, token: string, response: StoredHttpResponse, completedAt: string) {
    const result = await this.database.query(`
      UPDATE idempotency_keys SET response_status = $3, response_body = $4::jsonb,
        response_headers = $5::jsonb, completed_at = $6
      WHERE storage_key = $1 AND claim_token = $2 AND response_status IS NULL`, [
      key, token, response.status, JSON.stringify(response.body), JSON.stringify(response.headers), completedAt,
    ]);
    if (result.rowCount !== 1) throw new Error("Idempotency claim completion failed");
  }

  async abandonIdempotency(key: string, token: string) {
    await this.database.query("DELETE FROM idempotency_keys WHERE storage_key = $1 AND claim_token = $2 AND response_status IS NULL", [key, token]);
  }

  async listExpiredEvidence(cutoff: string, limit: number) {
    const result = await this.database.query<ReceiptRow>(`
      SELECT * FROM threat_receipts WHERE evidence_object_uri IS NOT NULL AND evidence_stored_at < $1
      ORDER BY evidence_stored_at, receipt_id LIMIT $2`, [cutoff, limit]);
    return result.rows.map(receiptFromRow);
  }

  async markEvidenceDeleted(receiptId: string, deletedAt: string) {
    await this.database.query(`
      UPDATE threat_receipts SET evidence_object_uri = NULL, evidence_size_bytes = NULL,
        evidence_stored_at = NULL, evidence_deleted_at = $2 WHERE receipt_id = $1`, [receiptId, deletedAt]);
  }

  async enqueueChainOperation(record: ChainOperationRecord) {
    const result = await this.database.query<ChainOperationRow>(`
      INSERT INTO chain_operations
        (operation_id, deduplication_key, tenant_id, operation_kind, payload, status, attempts,
         next_attempt_at, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10)
      ON CONFLICT (deduplication_key) DO NOTHING RETURNING *`, [
      record.operationId, record.deduplicationKey, record.tenantId, record.request.kind,
      JSON.stringify(record.request), record.status, record.attempts, record.nextAttemptAt,
      record.createdAt, record.updatedAt,
    ]);
    if (result.rows[0]) return { created: true, operation: chainOperationFromRow(result.rows[0]) };
    const existing = await this.database.query<ChainOperationRow>(
      "SELECT * FROM chain_operations WHERE deduplication_key = $1",
      [record.deduplicationKey],
    );
    if (!existing.rows[0]) throw new Error("Chain operation deduplication could not be resolved");
    return { created: false, operation: chainOperationFromRow(existing.rows[0]) };
  }

  async getChainOperation(operationId: string) {
    const result = await this.database.query<ChainOperationRow>(
      "SELECT * FROM chain_operations WHERE operation_id = $1",
      [operationId],
    );
    return result.rows[0] ? chainOperationFromRow(result.rows[0]) : undefined;
  }

  async claimNextChainOperation(now: string, claimExpiresAt: string): Promise<ClaimedChainOperation | undefined> {
    const claimToken = randomUUID();
    try {
      const result = await this.database.query<ChainOperationRow>(`
        UPDATE chain_operations SET claim_token = $1, claim_expires_at = $2
        WHERE operation_id = (
          SELECT operation_id FROM chain_operations
          WHERE status IN ('queued', 'prepared', 'submitted') AND next_attempt_at <= $3
            AND (claim_token IS NULL OR claim_expires_at <= $3)
            AND NOT EXISTS (
              SELECT 1 FROM chain_operations active
              WHERE active.claim_token IS NOT NULL AND active.claim_expires_at > $3
            )
          ORDER BY created_at, operation_id LIMIT 1
        )
        AND status IN ('queued', 'prepared', 'submitted')
        AND (claim_token IS NULL OR claim_expires_at <= $3)
        RETURNING *`, [claimToken, claimExpiresAt, now]);
      return result.rows[0] ? { operation: chainOperationFromRow(result.rows[0]), claimToken } : undefined;
    } catch (error) {
      if ((error as { code?: string }).code === "23505") return undefined;
      throw error;
    }
  }

  async updateClaimedChainOperation(operation: ChainOperationRecord, claimToken: string) {
    const result = await this.database.query(`
      UPDATE chain_operations SET status = $3, attempts = $4, next_attempt_at = $5,
        prepared_transaction_hash = $6, serialized_transaction = $7, transaction_hash = $8,
        block_number = $9, confirmations = $10, error_code = $11, updated_at = $12,
        claim_token = NULL, claim_expires_at = NULL
      WHERE operation_id = $1 AND claim_token = $2`, [
      operation.operationId, claimToken, operation.status, operation.attempts, operation.nextAttemptAt,
      operation.preparedTransactionHash ?? null, operation.serializedTransaction ?? null,
      operation.transactionHash ?? null, operation.blockNumber ?? null, operation.confirmations ?? null,
      operation.errorCode ?? null, operation.updatedAt,
    ]);
    if (result.rowCount !== 1) throw new Error("Chain operation claim update failed");
  }
}
