import { randomUUID } from "node:crypto";
import { ChainOperationCoordinator, defenseVersionKey, sha256Commitment, type ChainOperationRecord } from "@dadieng/contracts-client";
import { canonicalJson, contentHash, verifyDefenseBundle, type DefenseBundle } from "@dadieng/defense-module";
import { assertPublicReceiptSafe, verifyEvidenceCommitment } from "@dadieng/receipt-sanitizer";
import { runReplay, verifyReplayReport } from "@dadieng/replay-engine";
import {
  encryptedThreatEvidenceSchema,
  validatorAttestationSigningMessage,
  type ReplayReport,
} from "@dadieng/schemas";
import { getAddress, recoverMessageAddress, zeroHash } from "viem";
import type { ApiPrincipal } from "./auth.js";
import type {
  CreateDefenseRequest,
  CreateDefenseVersionRequest,
  CreateReceiptRequest,
  CreateReplayRequest,
  CreValidationCycleReceipt,
  QuarantineDefenseVersionRequest,
  SubmitValidatorAttestationRequest,
} from "./contracts.js";
import { ApiProblem } from "./errors.js";
import { InMemoryPrivateObjectStore, type PrivateObjectStore } from "./object-store.js";
import type { StableManifestPublisher } from "./manifest.js";
import type {
  ControlPlaneRepository,
  DefenseRecord,
  DefenseVersionRecord,
  ReceiptRecord,
  ReplayJobRecord,
  ValidationJobRecord,
} from "./repository.js";
import { RepositoryConflictError } from "./repository.js";

export interface ControlPlaneRuntime {
  createId(): string;
  now(): string;
}

export type ReplayExecutor = (bundle: DefenseBundle, request: CreateReplayRequest) => ReplayReport;
export type CreCycleRunner = (principal: ApiPrincipal) => Promise<CreValidationCycleReceipt>;

export interface ValidationNetwork {
  chainId: number;
  registryAddress: `0x${string}`;
  validationAddress: `0x${string}`;
}

export interface ValidatorIdentity {
  agentId: string;
  address: `0x${string}`;
}

const defaultRuntime: ControlPlaneRuntime = {
  createId: randomUUID,
  now: () => new Date().toISOString(),
};

const defaultReplayExecutor: ReplayExecutor = (bundle, request) => runReplay(bundle, {
  environment: request.environment,
  ...(request.thresholds ? {
    thresholds: {
      ...(request.thresholds.attackPassRate !== undefined ? { attackPassRate: request.thresholds.attackPassRate } : {}),
      ...(request.thresholds.controlPassRate !== undefined ? { controlPassRate: request.thresholds.controlPassRate } : {}),
      ...(request.thresholds.p95LatencyMs !== undefined ? { p95LatencyMs: request.thresholds.p95LatencyMs } : {}),
    },
  } : {}),
});

export class ControlPlaneService {
  constructor(
    readonly repository: ControlPlaneRepository,
    private readonly runtime: ControlPlaneRuntime = defaultRuntime,
    private readonly replayExecutor: ReplayExecutor = defaultReplayExecutor,
    readonly objectStore: PrivateObjectStore = new InMemoryPrivateObjectStore(),
    readonly chainOperations?: ChainOperationCoordinator,
    private readonly resolveChainIdentity?: (principal: ApiPrincipal) => string | undefined,
    private readonly validationNetwork?: ValidationNetwork,
    private readonly resolveValidatorIdentity?: (principal: ApiPrincipal) => ValidatorIdentity | undefined,
    readonly manifestPublisher?: StableManifestPublisher,
    private readonly creCycleRunner?: CreCycleRunner,
  ) {}

  async runCreValidationCycle(principal: ApiPrincipal): Promise<CreValidationCycleReceipt> {
    if (!this.creCycleRunner) {
      return { cycleId: this.runtime.createId(), status: "idle", reportHashes: [] };
    }
    return this.creCycleRunner(principal);
  }

  async checkHealth(): Promise<void> {
    try {
      await Promise.all([this.repository.healthCheck(), this.objectStore.healthCheck()]);
    } catch {
      throw new ApiProblem(503, "storage-unavailable", "Storage unavailable", "A required persistence service is unavailable.");
    }
  }

  async createReceipt(principal: ApiPrincipal, input: CreateReceiptRequest) {
    let receipt;
    try {
      receipt = assertPublicReceiptSafe(input.receipt);
    } catch {
      throw new ApiProblem(422, "unsafe-public-receipt", "Unsafe public receipt", "The public receipt failed the credential-safety checks.");
    }
    let evidenceMatches = false;
    try {
      evidenceMatches = verifyEvidenceCommitment(receipt, input.encryptedEvidence);
    } catch {
      throw new ApiProblem(422, "invalid-evidence-envelope", "Invalid evidence envelope", "The encrypted evidence envelope could not be verified.");
    }
    if (!evidenceMatches) {
      throw new ApiProblem(422, "evidence-commitment-mismatch", "Evidence commitment mismatch", "The encrypted evidence does not match the public receipt commitment.");
    }
    if (input.publishCommitment && !this.chainOperations) {
      throw new ApiProblem(503, "chain-adapter-unavailable", "Chain adapter unavailable", "The receipt is valid, but no chain transaction adapter is configured.");
    }
    if (input.publishCommitment && !receipt.reporter.erc8004Id) {
      throw new ApiProblem(422, "chain-identity-required", "Chain identity required", "An ERC-8004 reporter identity is required to publish a receipt commitment.");
    }
    if (input.publishCommitment) {
      const authorizedAgentId = this.resolveChainIdentity?.(principal);
      if (!authorizedAgentId || authorizedAgentId !== receipt.reporter.erc8004Id
        || (receipt.reporter.agentId !== undefined && receipt.reporter.agentId !== principal.subject)) {
        throw new ApiProblem(403, "chain-identity-mismatch", "Chain identity mismatch", "The authenticated subject is not authorized for the receipt's ERC-8004 identity.");
      }
    }
    const storedAt = this.runtime.now();
    const evidenceBytes = Buffer.from(canonicalJson(input.encryptedEvidence));
    const evidenceObject = await this.objectStore.put({
      tenantId: principal.tenantId,
      category: "evidence",
      objectId: receipt.receiptId,
      bytes: evidenceBytes,
      expectedHash: receipt.evidence.hash,
    });
    const record: ReceiptRecord = {
      tenantId: principal.tenantId,
      receipt,
      evidenceHash: receipt.evidence.hash,
      evidenceObject: {
        uri: evidenceObject.uri,
        hash: evidenceObject.contentHash,
        sizeBytes: evidenceObject.sizeBytes,
        storedAt,
      },
      createdAt: storedAt,
    };
    try {
      const result = await this.repository.saveReceipt(record);
      if (!result.created && result.record.evidenceObject?.uri !== evidenceObject.uri) {
        await this.objectStore.delete(evidenceObject.uri);
      }
      return await this.receiptResult(principal, result.record, input.publishCommitment, !result.created);
    } catch (error) {
      await this.objectStore.delete(evidenceObject.uri);
      if (error instanceof RepositoryConflictError && error.conflict === "receipt-id") {
        throw new ApiProblem(409, "receipt-id-conflict", "Receipt ID conflict", "The receipt ID is already registered.");
      }
      throw error;
    }
  }

  async getPublicReceipt(receiptId: string) {
    const record = await this.repository.getReceipt(receiptId);
    if (!record) throw new ApiProblem(404, "receipt-not-found", "Receipt not found", "No public receipt exists for this ID.");
    return { receipt: record.receipt, resolution: { status: "unresolved" as const } };
  }

  async getPrivateEvidence(principal: ApiPrincipal, receiptId: string) {
    const record = await this.repository.getReceiptForTenant(principal.tenantId, receiptId);
    if (!record) {
      throw new ApiProblem(404, "receipt-not-found", "Receipt not found", "No receipt exists for this tenant and ID.");
    }
    if (!record.evidenceObject) {
      throw new ApiProblem(410, "evidence-expired", "Evidence expired", "The retained evidence object has been deleted.");
    }
    const bytes = await this.objectStore.get(record.evidenceObject.uri, record.evidenceHash);
    return encryptedThreatEvidenceSchema.parse(JSON.parse(Buffer.from(bytes).toString("utf8")));
  }

  async createDefense(principal: ApiPrincipal, input: CreateDefenseRequest): Promise<DefenseRecord> {
    if (input.authorAgentId !== principal.subject) {
      throw new ApiProblem(403, "author-mismatch", "Author mismatch", "A defense author must match the authenticated subject.");
    }
    const record = { ...input, createdAt: this.runtime.now() };
    if (!await this.repository.saveDefense(record)) {
      throw new ApiProblem(409, "defense-conflict", "Defense already exists", "The defense ID is already registered.");
    }
    return record;
  }

  async createDefenseVersion(
    principal: ApiPrincipal,
    defenseId: string,
    input: CreateDefenseVersionRequest,
  ): Promise<DefenseVersionRecord> {
    const defense = await this.repository.getDefense(defenseId);
    if (!defense) throw new ApiProblem(404, "defense-not-found", "Defense not found", "Register the defense before publishing a version.");
    if (defense.authorAgentId !== principal.subject) {
      throw new ApiProblem(403, "not-defense-author", "Not defense author", "Only the registered author may publish a version.");
    }
    let bundle;
    try {
      bundle = verifyDefenseBundle(input.bundle);
    } catch {
      throw new ApiProblem(422, "invalid-defense-bundle", "Invalid defense bundle", "The bundle hashes or signed contents could not be verified.");
    }
    if (bundle.manifest.defenseId !== defenseId) {
      throw new ApiProblem(422, "defense-id-mismatch", "Defense ID mismatch", "The bundle identity does not match the route.");
    }
    const defenseVersionId = `${defenseId}@${bundle.manifest.version}`;
    const record: DefenseVersionRecord = {
      defenseVersionId,
      defenseId,
      bundle,
      status: "candidate",
      createdAt: this.runtime.now(),
    };
    if (!await this.repository.saveDefenseVersion(record)) {
      throw new ApiProblem(409, "version-conflict", "Defense version already exists", "Published versions are immutable.");
    }
    return record;
  }

  async createReplay(principal: ApiPrincipal, input: CreateReplayRequest): Promise<ReplayJobRecord> {
    if (!await this.repository.getDefenseVersion(input.defenseVersionId)) {
      throw new ApiProblem(404, "defense-version-not-found", "Defense version not found", "Publish the exact version before scheduling replay.");
    }
    const now = this.runtime.now();
    const record: ReplayJobRecord = {
      replayId: this.runtime.createId(),
      tenantId: principal.tenantId,
      request: input,
      status: "queued",
      createdAt: now,
      updatedAt: now,
    };
    await this.repository.saveReplay(record);
    return record;
  }

  async getReplay(replayId: string): Promise<ReplayJobRecord> {
    const record = await this.repository.getReplay(replayId);
    if (!record) throw new ApiProblem(404, "replay-not-found", "Replay not found", "No replay exists for this ID.");
    return record;
  }

  async getChainOperation(operationId: string) {
    if (!this.chainOperations) {
      throw new ApiProblem(503, "chain-adapter-unavailable", "Chain adapter unavailable", "No chain transaction adapter is configured.");
    }
    const operation = await this.chainOperations.get(operationId);
    if (!operation) throw new ApiProblem(404, "operation-not-found", "Operation not found", "No chain operation exists for this ID.");
    return this.publicChainOperation(operation);
  }

  async quarantineDefenseVersion(
    principal: ApiPrincipal,
    defenseVersionId: string,
    input: QuarantineDefenseVersionRequest,
  ) {
    if (!this.chainOperations) {
      throw new ApiProblem(503, "chain-adapter-unavailable", "Chain adapter unavailable", "Quarantine requires a configured Monad transaction adapter.");
    }
    const version = await this.repository.getDefenseVersion(defenseVersionId);
    if (!version) {
      throw new ApiProblem(404, "defense-version-not-found", "Defense version not found", "The requested version cannot be quarantined.");
    }
    let replacementVersionKey: `0x${string}` = zeroHash;
    if (input.replacementDefenseVersionId) {
      const replacement = await this.repository.getDefenseVersion(input.replacementDefenseVersionId);
      if (!replacement || replacement.defenseId !== version.defenseId || replacement.defenseVersionId === defenseVersionId) {
        throw new ApiProblem(422, "invalid-replacement-version", "Invalid replacement version", "A replacement must be another published version of the same defense.");
      }
      replacementVersionKey = defenseVersionKey(replacement.defenseId, replacement.bundle.manifest.version);
    }
    const operation = (await this.chainOperations.enqueue({
      tenantId: principal.tenantId,
      deduplicationKey: `quarantine:${defenseVersionId}:${input.evidenceHash}:${input.replacementDefenseVersionId ?? "none"}`,
      request: {
        kind: "quarantine-version",
        versionKey: defenseVersionKey(version.defenseId, version.bundle.manifest.version),
        reasonCode: input.reasonCode,
        evidenceHash: sha256Commitment(input.evidenceHash),
        replacementVersionKey,
      },
    })).operation;
    return {
      defenseVersionId,
      status: "pending" as const,
      reasonCode: input.reasonCode,
      evidenceHash: input.evidenceHash,
      replacementDefenseVersionId: input.replacementDefenseVersionId,
      operation: this.publicChainOperation(operation),
    };
  }

  async runNextChainOperation(): Promise<ChainOperationRecord | undefined> {
    if (!this.chainOperations) return undefined;
    return this.chainOperations.runNext();
  }

  async runNextReplay(): Promise<ReplayJobRecord | undefined> {
    const job = await this.repository.claimNextReplay(this.runtime.now());
    if (!job) return undefined;

    const version = await this.repository.getDefenseVersion(job.request.defenseVersionId);
    if (!version) return this.failReplay(job, "DEFENSE_VERSION_MISSING");
    try {
      const report = this.replayExecutor(version.bundle, job.request);
      verifyReplayReport(report, version.bundle);
      job.status = "completed";
      job.report = report;
      job.updatedAt = this.runtime.now();
      await this.repository.saveReplay(job);
      if (this.validationNetwork) {
        const now = this.runtime.now();
        await this.repository.saveValidationJob({
          jobId: this.runtime.createId(),
          tenantId: job.tenantId,
          replayId: job.replayId,
          defenseVersionId: job.request.defenseVersionId,
          versionKey: defenseVersionKey(version.bundle.manifest.defenseId, version.bundle.manifest.version),
          chainId: this.validationNetwork.chainId,
          registryAddress: this.validationNetwork.registryAddress,
          validationAddress: this.validationNetwork.validationAddress,
          bundle: version.bundle,
          environment: job.request.environment,
          ...(job.request.thresholds ? { thresholds: job.request.thresholds } : {}),
          canonicalReportHash: report.reportHash,
          status: "open",
          createdAt: now,
          updatedAt: now,
        });
      }
      return job;
    } catch {
      return this.failReplay(job, "REPLAY_EXECUTION_FAILED");
    }
  }

  async listValidationJobs(principal: ApiPrincipal) {
    const jobs = await this.repository.listValidationJobs(principal.tenantId, principal.subject, this.runtime.now());
    return jobs.map((job) => this.publicValidationJob(job, job.claimedBy === principal.subject));
  }

  async claimValidationJob(principal: ApiPrincipal, jobId: string) {
    const identity = this.resolveValidatorIdentity?.(principal);
    if (!identity) {
      throw new ApiProblem(403, "validator-identity-required", "Validator identity required", "The authenticated subject has no registered validator identity.");
    }
    const job = await this.repository.getValidationJob(jobId);
    if (!job || job.tenantId !== principal.tenantId) {
      throw new ApiProblem(404, "validation-job-not-found", "Validation job not found", "No validation job exists for this tenant and ID.");
    }
    if (job.bundle.manifest.authorAgentId === identity.agentId) {
      throw new ApiProblem(403, "self-attestation-forbidden", "Self attestation forbidden", "A defense author cannot validate their own version.");
    }
    const now = this.runtime.now();
    const claimed = await this.repository.claimValidationJob(
      jobId,
      principal.tenantId,
      principal.subject,
      identity.agentId,
      getAddress(identity.address),
      now,
      new Date(Date.parse(now) + 30 * 60_000).toISOString(),
    );
    if (!claimed) {
      throw new ApiProblem(409, "validation-job-unavailable", "Validation job unavailable", "Another validator currently owns this job claim.");
    }
    return this.publicValidationJob(claimed, true);
  }

  async submitValidatorAttestation(principal: ApiPrincipal, input: SubmitValidatorAttestationRequest) {
    const job = await this.repository.getValidationJob(input.jobId);
    if (!job || job.tenantId !== principal.tenantId) {
      throw new ApiProblem(404, "validation-job-not-found", "Validation job not found", "No validation job exists for this tenant and ID.");
    }
    if (job.status !== "claimed" || job.claimedBy !== principal.subject || !job.validatorAddress || !job.validatorAgentId) {
      throw new ApiProblem(409, "validation-job-not-claimed", "Validation job not claimed", "The authenticated validator does not own this job claim.");
    }
    if (!job.claimExpiresAt || job.claimExpiresAt <= this.runtime.now()) {
      throw new ApiProblem(409, "validation-claim-expired", "Validation claim expired", "Claim the validation job again before submitting an attestation.");
    }
    let report: ReplayReport;
    try {
      report = verifyReplayReport(input.report, job.bundle);
    } catch {
      throw new ApiProblem(422, "invalid-independent-report", "Invalid independent report", "The report or its artifact commitments could not be verified.");
    }
    if (report.reportHash === job.canonicalReportHash) {
      throw new ApiProblem(422, "non-independent-report", "Non independent report", "Validators must produce their own replay report instead of signing the canonical result.");
    }
    const attestation = input.attestation;
    if (attestation.validatorAgentId !== job.validatorAgentId
      || attestation.chainId !== job.chainId
      || attestation.registryAddress.toLowerCase() !== job.registryAddress.toLowerCase()
      || attestation.defenseVersionId !== job.defenseVersionId
      || attestation.artifactHash !== job.bundle.manifest.artifactHash
      || attestation.suiteHash !== job.bundle.manifest.suiteHash
      || attestation.reportHash !== report.reportHash
      || attestation.passed !== report.releaseEligible) {
      throw new ApiProblem(422, "attestation-mismatch", "Attestation mismatch", "The signed attestation does not match the claimed job and independent report.");
    }
    const signedAt = Date.parse(attestation.signedAt);
    const now = Date.parse(this.runtime.now());
    if (signedAt < Date.parse(job.updatedAt) || signedAt > now + 5 * 60_000) {
      throw new ApiProblem(422, "invalid-attestation-time", "Invalid attestation time", "The attestation must be signed after the claim and cannot be more than five minutes in the future.");
    }
    if (Date.parse(report.startedAt) < Date.parse(job.updatedAt) || Date.parse(report.completedAt) > signedAt) {
      throw new ApiProblem(422, "invalid-independent-report-time", "Invalid independent report time", "The independent replay must run after the validator claims the job and finish before signing.");
    }
    const { signature, ...unsigned } = attestation;
    let signer: `0x${string}`;
    try {
      signer = await recoverMessageAddress({ message: validatorAttestationSigningMessage(unsigned), signature: signature as `0x${string}` });
    } catch {
      throw new ApiProblem(422, "invalid-attestation-signature", "Invalid attestation signature", "The attestation signature could not be recovered.");
    }
    if (signer.toLowerCase() !== job.validatorAddress.toLowerCase()) {
      throw new ApiProblem(403, "validator-signature-mismatch", "Validator signature mismatch", "The attestation was not signed by the claimed validator wallet.");
    }
    const completed: ValidationJobRecord = {
      ...job,
      status: "submitted",
      report,
      attestation,
      transactionHash: input.transactionHash as `0x${string}`,
      updatedAt: new Date(now).toISOString(),
    };
    delete completed.claimExpiresAt;
    if (!await this.repository.completeValidationJob(completed, principal.subject)) {
      throw new ApiProblem(409, "validation-job-conflict", "Validation job conflict", "The job claim changed before the attestation was recorded.");
    }
    return { jobId: job.jobId, attestationId: attestation.attestationId, status: "submitted" as const, transactionHash: input.transactionHash };
  }

  async getPublicAttestation(attestationId: string) {
    const match = await this.repository.getValidationJobByAttestationId(attestationId);
    if (!match?.attestation || !match.report) {
      throw new ApiProblem(404, "attestation-not-found", "Attestation not found", "No submitted attestation exists for this ID.");
    }
    return { attestation: match.attestation, report: match.report, transactionHash: match.transactionHash };
  }

  async getStableManifest(channel: string) {
    if (channel !== "stable") {
      throw new ApiProblem(404, "channel-not-found", "Channel not found", "Only the stable release channel is available.");
    }
    if (!this.manifestPublisher) {
      throw new ApiProblem(503, "manifest-publisher-unavailable", "Manifest publisher unavailable", "Stable manifest publication is not configured.");
    }
    try {
      return await this.manifestPublisher.get(channel);
    } catch {
      throw new ApiProblem(503, "manifest-refresh-failed", "Manifest refresh failed", "The stable manifest could not be verified and refreshed.");
    }
  }

  async getPublicDefenseBundle(defenseVersionId: string) {
    const version = await this.repository.getDefenseVersion(defenseVersionId);
    if (!version) throw new ApiProblem(404, "defense-version-not-found", "Defense version not found", "No public defense bundle exists for this version.");
    return verifyDefenseBundle(version.bundle);
  }

  async purgeEvidenceBefore(cutoff: string, limit = 100): Promise<number> {
    if (Number.isNaN(Date.parse(cutoff))) throw new Error("Retention cutoff must be an RFC 3339 timestamp");
    if (!Number.isInteger(limit) || limit < 1 || limit > 1_000) throw new Error("Retention purge limit must be between 1 and 1000");
    const records = await this.repository.listExpiredEvidence(cutoff, limit);
    let deleted = 0;
    for (const record of records) {
      if (!record.evidenceObject) continue;
      await this.objectStore.delete(record.evidenceObject.uri);
      await this.repository.markEvidenceDeleted(record.receipt.receiptId, this.runtime.now());
      deleted += 1;
    }
    return deleted;
  }

  private async failReplay(job: ReplayJobRecord, errorCode: string): Promise<ReplayJobRecord> {
    job.status = "failed";
    job.errorCode = errorCode;
    job.updatedAt = this.runtime.now();
    await this.repository.saveReplay(job);
    return job;
  }

  private async receiptResult(
    principal: ApiPrincipal,
    record: ReceiptRecord,
    publishCommitment: boolean,
    duplicate: boolean,
  ) {
    const operation = publishCommitment
      ? (await this.chainOperations!.enqueue({
          tenantId: principal.tenantId,
          deduplicationKey: `receipt:${record.receipt.receiptId}:${contentHash(record.receipt)}`,
          request: {
            kind: "publish-receipt",
            receiptId: record.receipt.receiptId,
            receiptHash: sha256Commitment(contentHash(record.receipt)),
            evidenceHash: sha256Commitment(record.receipt.evidence.hash),
            attackClass: record.receipt.classification.attackClass,
            reporterAgentId: record.receipt.reporter.erc8004Id!,
          },
        })).operation
      : undefined;
    return {
      receiptId: record.receipt.receiptId,
      status: duplicate ? "duplicate" as const : "sanitized" as const,
      publicHash: contentHash(record.receipt),
      chain: {
        status: operation
          ? operation.status === "confirmed" ? "confirmed" as const
            : operation.status === "failed" ? "failed" as const
              : "pending" as const
          : "not-requested" as const,
        operationId: operation?.operationId ?? null,
      },
    };
  }

  private publicChainOperation(operation: ChainOperationRecord) {
    return {
      operationId: operation.operationId,
      kind: operation.request.kind,
      status: operation.status,
      stage: operation.status,
      attempts: operation.attempts,
      transactionHash: operation.transactionHash ?? operation.preparedTransactionHash ?? null,
      confirmations: operation.confirmations ?? 0,
      blockNumber: operation.blockNumber ?? null,
      errorCode: operation.errorCode ?? null,
      updatedAt: operation.updatedAt,
      retrySafe: operation.status !== "confirmed" && operation.status !== "failed",
    };
  }

  private publicValidationJob(job: ValidationJobRecord, includeClaim: boolean) {
    return {
      jobId: job.jobId,
      defenseVersionId: job.defenseVersionId,
      versionKey: job.versionKey,
      chainId: job.chainId,
      registryAddress: job.registryAddress,
      validationAddress: job.validationAddress,
      bundle: job.bundle,
      environment: job.environment,
      ...(job.thresholds ? { thresholds: job.thresholds } : {}),
      status: includeClaim ? job.status : "open",
      ...(includeClaim && job.validatorAgentId ? { validatorAgentId: job.validatorAgentId } : {}),
      ...(includeClaim && job.validatorAddress ? { validatorAddress: job.validatorAddress } : {}),
      ...(includeClaim && job.claimExpiresAt ? { claimExpiresAt: job.claimExpiresAt } : {}),
    };
  }
}
