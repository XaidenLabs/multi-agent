import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type {
  ChainOperationRecord,
  ChainOperationRepository,
  ClaimedChainOperation,
} from "@dadieng/contracts-client";
import { replayReportSchema, validatorAttestationSchema, type ReplayReport, type ValidatorAttestation } from "@dadieng/schemas";
import { validationJobSchema, type ValidationJob } from "./index.js";

export interface ValidatorCredentials {
  apiUrl: string;
  token: string;
}

interface ValidatorState {
  jobs: Record<string, ValidationJob>;
  reports: Record<string, ReplayReport>;
  attestations: Record<string, ValidatorAttestation>;
  chainOperations: Record<string, ChainOperationRecord>;
  deduplication: Record<string, string>;
  claims: Record<string, { token: string; expiresAt: string }>;
}

function emptyState(): ValidatorState {
  return { jobs: {}, reports: {}, attestations: {}, chainOperations: {}, deduplication: {}, claims: {} };
}

function copy<T>(value: T): T {
  return structuredClone(value);
}

export class ValidatorWorkspace implements ChainOperationRepository {
  constructor(readonly root: string) {}

  private get credentialsPath() { return join(this.root, "credentials.json"); }
  private get statePath() { return join(this.root, "state.json"); }

  async saveCredentials(credentials: ValidatorCredentials): Promise<void> {
    if (!/^https?:\/\//.test(credentials.apiUrl) || credentials.token.length < 16) throw new Error("Invalid Dadieng credentials");
    await this.writePrivate(this.credentialsPath, credentials);
  }

  async loadCredentials(): Promise<ValidatorCredentials> {
    const value = JSON.parse(await readFile(this.credentialsPath, "utf8")) as Partial<ValidatorCredentials>;
    if (!value.apiUrl || !value.token) throw new Error("Run dadieng-validator login first");
    return { apiUrl: value.apiUrl, token: value.token };
  }

  async saveJob(job: ValidationJob): Promise<void> {
    const parsed = validationJobSchema.parse(job) as ValidationJob;
    await this.update((state) => { state.jobs[parsed.jobId] = parsed; });
  }

  async getJob(jobId: string): Promise<ValidationJob | undefined> {
    const value = (await this.read()).jobs[jobId];
    return value ? validationJobSchema.parse(value) as ValidationJob : undefined;
  }

  async saveReport(jobId: string, report: ReplayReport): Promise<void> {
    const parsed = replayReportSchema.parse(report);
    await this.update((state) => { state.reports[jobId] = parsed; });
  }

  async getReport(jobId: string): Promise<ReplayReport | undefined> {
    const value = (await this.read()).reports[jobId];
    return value ? replayReportSchema.parse(value) : undefined;
  }

  async saveAttestation(jobId: string, attestation: ValidatorAttestation): Promise<void> {
    const parsed = validatorAttestationSchema.parse(attestation);
    await this.update((state) => { state.attestations[jobId] = parsed; });
  }

  async getAttestation(jobId: string): Promise<ValidatorAttestation | undefined> {
    const value = (await this.read()).attestations[jobId];
    return value ? validatorAttestationSchema.parse(value) : undefined;
  }

  async enqueueChainOperation(record: ChainOperationRecord) {
    let result!: { created: boolean; operation: ChainOperationRecord };
    await this.update((state) => {
      const existingId = state.deduplication[record.deduplicationKey];
      if (existingId && state.chainOperations[existingId]) {
        result = { created: false, operation: copy(state.chainOperations[existingId]) };
        return;
      }
      state.chainOperations[record.operationId] = copy(record);
      state.deduplication[record.deduplicationKey] = record.operationId;
      result = { created: true, operation: copy(record) };
    });
    return result;
  }

  async getChainOperation(operationId: string) {
    const value = (await this.read()).chainOperations[operationId];
    return value ? copy(value) : undefined;
  }

  async claimNextChainOperation(now: string, claimExpiresAt: string): Promise<ClaimedChainOperation | undefined> {
    let result: ClaimedChainOperation | undefined;
    await this.update((state) => {
      if (Object.values(state.claims).some((claim) => claim.expiresAt > now)) return;
      const operation = Object.values(state.chainOperations)
        .filter((candidate) => candidate.status !== "confirmed" && candidate.status !== "failed" && candidate.nextAttemptAt <= now)
        .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.operationId.localeCompare(right.operationId))
        .find((candidate) => !state.claims[candidate.operationId] || state.claims[candidate.operationId]!.expiresAt <= now);
      if (!operation) return;
      const claimToken = randomUUID();
      state.claims[operation.operationId] = { token: claimToken, expiresAt: claimExpiresAt };
      result = { operation: copy(operation), claimToken };
    });
    return result;
  }

  async updateClaimedChainOperation(operation: ChainOperationRecord, claimToken: string): Promise<void> {
    await this.update((state) => {
      if (state.claims[operation.operationId]?.token !== claimToken) throw new Error("Validator operation claim update failed");
      state.chainOperations[operation.operationId] = copy(operation);
      delete state.claims[operation.operationId];
    });
  }

  private async read(): Promise<ValidatorState> {
    try {
      const state = JSON.parse(await readFile(this.statePath, "utf8")) as ValidatorState;
      return { ...emptyState(), ...state };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return emptyState();
      throw error;
    }
  }

  private async update(change: (state: ValidatorState) => void): Promise<void> {
    const state = await this.read();
    change(state);
    await this.writePrivate(this.statePath, state);
  }

  private async writePrivate(path: string, value: unknown): Promise<void> {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await chmod(dirname(path), 0o700);
    const temporary = `${path}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, path);
    await chmod(path, 0o600);
  }
}
