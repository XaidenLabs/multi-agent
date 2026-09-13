import type { ReplayReport, ValidatorAttestation } from "@dadieng/schemas";
import { validationJobSchema, type ValidationJob } from "./index.js";

export interface ValidatorApiConfig {
  apiUrl: string;
  token: string;
}

export class ValidatorApiClient {
  constructor(private readonly config: ValidatorApiConfig) {
    if (!/^https?:\/\//.test(config.apiUrl)) throw new Error("Dadieng API URL must use HTTP or HTTPS");
    if (config.token.length < 16) throw new Error("Dadieng API token must contain at least 16 characters");
  }

  async listJobs(): Promise<ValidationJob[]> {
    const body = await this.request("/v1/validators/jobs");
    if (!body || typeof body !== "object" || !Array.isArray((body as { jobs?: unknown }).jobs)) throw new Error("Dadieng API returned an invalid job list");
    return (body as { jobs: unknown[] }).jobs.map((job) => validationJobSchema.parse(job) as ValidationJob);
  }

  async claimJob(jobId: string): Promise<ValidationJob> {
    const body = await this.request(`/v1/validators/jobs/${encodeURIComponent(jobId)}/claim`, {
      method: "POST",
      body: {},
      idempotencyKey: `claim-${jobId}`,
    });
    return validationJobSchema.parse((body as { job?: unknown }).job) as ValidationJob;
  }

  async submitAttestation(input: {
    jobId: string;
    report: ReplayReport;
    attestation: ValidatorAttestation;
    transactionHash: `0x${string}`;
  }): Promise<unknown> {
    return this.request("/v1/attestations", {
      method: "POST",
      body: input,
      idempotencyKey: `attest-${input.attestation.attestationId}`,
    });
  }

  private async request(path: string, options?: { method: "POST"; body: unknown; idempotencyKey: string }): Promise<unknown> {
    const response = await fetch(new URL(path, this.config.apiUrl), {
      method: options?.method ?? "GET",
      headers: {
        authorization: `Bearer ${this.config.token}`,
        ...(options ? { "content-type": "application/json", "idempotency-key": options.idempotencyKey } : {}),
      },
      ...(options ? { body: JSON.stringify(options.body) } : {}),
    });
    const body = await response.json() as unknown;
    if (!response.ok) {
      const detail = body && typeof body === "object" && "detail" in body ? String((body as { detail: unknown }).detail) : `HTTP ${response.status}`;
      throw new Error(`Dadieng API request failed: ${detail}`);
    }
    return body;
  }
}
