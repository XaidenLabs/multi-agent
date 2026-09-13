import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpBoundaryBundle } from "@dadieng/defense-module/mcp-boundary";
import { defenseVersionKey, sha256Commitment, type ChainOperationRecord } from "@dadieng/contracts-client";
import {
  ControlPlaneHttpApp,
  ControlPlaneService,
  InMemoryControlPlaneRepository,
  StaticApiKeyAuthenticator,
  type ApiPrincipal,
} from "@dadieng/control-plane";
import { runReplay, sha256Bytes } from "@dadieng/replay-engine";
import {
  createSignedAttestation,
  runIndependentReplay,
  verifyAttestationSignature,
  verifyValidationJob,
  type ValidationJob,
  type ValidatorChainReader,
} from "@dadieng/validator-cli";
import { ValidatorWorkspace } from "../apps/validator-cli/src/storage.js";
import { privateKeyToAccount } from "viem/accounts";

const FIXED_TIME = "2026-09-04T12:00:00.000Z";
const PRIVATE_KEY = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const;
const OTHER_PRIVATE_KEY = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" as const;
const account = privateKeyToAccount(PRIVATE_KEY);
const registryAddress = "0x1111111111111111111111111111111111111111" as const;
const validationAddress = "0x2222222222222222222222222222222222222222" as const;
const environment = {
  imageDigest: sha256Bytes("validator-image-v1"),
  dependencyLockHash: sha256Bytes("validator-lock-v1"),
  runtime: "node-22",
  seed: 42,
  network: "none" as const,
  filesystem: "read-only" as const,
  clock: "deterministic" as const,
};

function replayRuntime(runId: string) {
  return {
    createRunId: () => runId,
    now: () => FIXED_TIME,
    measure: (_caseId: string, operation: () => unknown) => ({ value: operation(), durationMs: 2 }),
  };
}

function job(): ValidationJob {
  const bundle = createMcpBoundaryBundle();
  return {
    jobId: "validation_job_1",
    defenseVersionId: `${bundle.manifest.defenseId}@${bundle.manifest.version}`,
    versionKey: defenseVersionKey(bundle.manifest.defenseId, bundle.manifest.version),
    chainId: 10_143,
    registryAddress,
    validationAddress,
    bundle,
    environment,
    status: "claimed",
    validatorAgentId: "4001",
    validatorAddress: account.address,
    claimExpiresAt: "2026-09-04T12:30:00.000Z",
  };
}

function reader(overrides: Partial<ValidatorChainReader> = {}): ValidatorChainReader {
  const current = job();
  const bundle = createMcpBoundaryBundle();
  return {
    getCode: async () => "0x6000",
    getVersion: async () => ({
      status: 2,
      manifestHash: sha256Commitment((await import("@dadieng/defense-module")).verifyDefenseBundle(bundle).manifestHash),
      artifactHash: sha256Commitment(bundle.manifest.artifactHash),
      authorAgentId: 3001n,
    }),
    getValidatorAgentId: async () => BigInt(current.validatorAgentId!),
    ...overrides,
  };
}

const temporaryRoots: string[] = [];
afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("Phase 11 independent validator", () => {
  it("verifies the exact bundle, Monad commitment, candidate state, and validator identity", async () => {
    const result = await verifyValidationJob(job(), reader(), () => FIXED_TIME);
    expect(result.bundle.manifest.defenseId).toBe(job().bundle.manifest.defenseId);
  });

  it("fails closed on a mismatched Monad commitment, missing contract, or self-attestation", async () => {
    await expect(verifyValidationJob(job(), reader({
      getVersion: async () => ({ status: 2, manifestHash: `0x${"00".repeat(32)}`, artifactHash: `0x${"00".repeat(32)}`, authorAgentId: 3001n }),
    }), () => FIXED_TIME)).rejects.toThrow("commitment");
    await expect(verifyValidationJob(job(), reader({ getCode: async () => "0x" }), () => FIXED_TIME)).rejects.toThrow("not deployed");
    await expect(verifyValidationJob(job(), reader({
      getVersion: async () => {
        const bundle = createMcpBoundaryBundle();
        const verified = (await import("@dadieng/defense-module")).verifyDefenseBundle(bundle);
        return { status: 2, manifestHash: sha256Commitment(verified.manifestHash), artifactHash: sha256Commitment(bundle.manifest.artifactHash), authorAgentId: 4001n };
      },
    }), () => FIXED_TIME)).rejects.toThrow("own versions");
  });

  it("reruns the suite and signs a report-bound attestation with the claimed wallet", async () => {
    const claimed = job();
    const report = runIndependentReplay(claimed, {
      replay: replayRuntime("independent_run_1"),
      createAttestationId: () => "attestation_1",
      now: () => FIXED_TIME,
    });
    const attestation = await createSignedAttestation(claimed, report, PRIVATE_KEY, {
      createAttestationId: () => "attestation_1",
      now: () => FIXED_TIME,
    });

    expect(attestation.reportHash).toBe(report.reportHash);
    expect(attestation.passed).toBe(report.releaseEligible);
    expect(await verifyAttestationSignature(attestation, account.address)).toBe(true);
    await expect(createSignedAttestation(claimed, report, OTHER_PRIVATE_KEY)).rejects.toThrow("does not match");
  });

  it("persists credentials, reports, and prepared operations with owner-only permissions", async () => {
    const root = await mkdtemp(join(tmpdir(), "dadieng-validator-"));
    temporaryRoots.push(root);
    const workspace = new ValidatorWorkspace(root);
    await workspace.saveCredentials({ apiUrl: "https://api.dadieng.dev", token: "validator-token-00000001" });
    await workspace.saveJob(job());
    const report = runIndependentReplay(job(), { replay: replayRuntime("independent_run_2"), createAttestationId: () => "att_2", now: () => FIXED_TIME });
    await workspace.saveReport(job().jobId, report);

    expect(await workspace.loadCredentials()).toEqual({ apiUrl: "https://api.dadieng.dev", token: "validator-token-00000001" });
    expect((await workspace.getReport(job().jobId))?.reportHash).toBe(report.reportHash);
    expect((await stat(join(root, "credentials.json"))).mode & 0o777).toBe(0o600);
    expect((await stat(join(root, "state.json"))).mode & 0o777).toBe(0o600);
  });

  it("deduplicates durable validator transactions and recovers expired local claims", async () => {
    const root = await mkdtemp(join(tmpdir(), "dadieng-validator-"));
    temporaryRoots.push(root);
    const workspace = new ValidatorWorkspace(root);
    const operation: ChainOperationRecord = {
      operationId: "operation_1",
      deduplicationKey: "attestation:one",
      tenantId: "validator-local",
      request: { kind: "promote-version", versionKey: job().versionKey },
      status: "queued",
      attempts: 0,
      nextAttemptAt: FIXED_TIME,
      createdAt: FIXED_TIME,
      updatedAt: FIXED_TIME,
    };
    expect((await workspace.enqueueChainOperation(operation)).created).toBe(true);
    expect((await workspace.enqueueChainOperation({ ...operation, operationId: "operation_2" })).operation.operationId).toBe("operation_1");
    const first = await workspace.claimNextChainOperation(FIXED_TIME, "2026-09-04T12:01:00.000Z");
    expect(first?.operation.operationId).toBe("operation_1");
    expect(await workspace.claimNextChainOperation("2026-09-04T12:00:30.000Z", "2026-09-04T12:02:00.000Z")).toBeUndefined();
    expect((await workspace.claimNextChainOperation("2026-09-04T12:01:01.000Z", "2026-09-04T12:02:00.000Z"))?.operation.operationId).toBe("operation_1");
  });

  it("opens, claims, and records an independently signed validation through the API", async () => {
    let sequence = 0;
    const repository = new InMemoryControlPlaneRepository();
    const service = new ControlPlaneService(
      repository,
      { createId: () => `id_${++sequence}`, now: () => FIXED_TIME },
      (bundle, request) => runReplay(bundle, { environment: request.environment, runtime: replayRuntime("canonical_run") }),
      undefined,
      undefined,
      undefined,
      { chainId: 10_143, registryAddress, validationAddress },
      (principal) => principal.subject === "validator.one" ? { agentId: "4001", address: account.address } : undefined,
    );
    const authorToken = "author-token-0000000001";
    const validatorToken = "validator-token-0000001";
    const authenticator = new StaticApiKeyAuthenticator([
      { token: authorToken, principal: { subject: "dadieng.core", tenantId: "tenant", scopes: ["defenses:write", "replays:write"] } },
      { token: validatorToken, principal: { subject: "validator.one", tenantId: "tenant", scopes: ["validators:read", "validators:write"] } },
    ]);
    const app = new ControlPlaneHttpApp(service, authenticator);
    const post = (path: string, body: unknown, token: string, key: string) => app.handle(new Request(`http://dadieng.local${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "idempotency-key": key },
      body: JSON.stringify(body),
    }));
    const bundle = createMcpBoundaryBundle();
    expect((await post("/v1/defenses", { defenseId: bundle.manifest.defenseId, name: bundle.manifest.name, authorAgentId: "dadieng.core" }, authorToken, "defense")).status).toBe(201);
    expect((await post(`/v1/defenses/${bundle.manifest.defenseId}/versions`, { bundle }, authorToken, "version")).status).toBe(201);
    const replayResponse = await post("/v1/replays", { defenseVersionId: `${bundle.manifest.defenseId}@${bundle.manifest.version}`, environment }, authorToken, "replay");
    expect(replayResponse.status).toBe(202);
    const replayId = (await replayResponse.json() as { replayId: string }).replayId;
    await service.runNextReplay();

    const listResponse = await app.handle(new Request("http://dadieng.local/v1/validators/jobs", { headers: { authorization: `Bearer ${validatorToken}` } }));
    const list = await listResponse.json() as { jobs: ValidationJob[] };
    expect(list.jobs).toHaveLength(1);
    expect(JSON.stringify(list)).not.toContain("canonical_run");
    const claimedResponse = await post(`/v1/validators/jobs/${list.jobs[0]!.jobId}/claim`, {}, validatorToken, "claim");
    const claimed = (await claimedResponse.json() as { job: ValidationJob }).job;
    expect(claimed.validatorAgentId).toBe("4001");

    const independent = runIndependentReplay(claimed, { replay: replayRuntime("independent_run"), createAttestationId: () => "attestation_api", now: () => FIXED_TIME });
    const attestation = await createSignedAttestation(claimed, independent, PRIVATE_KEY, { createAttestationId: () => "attestation_api", now: () => FIXED_TIME });
    const canonical = (await service.getReplay(replayId)).report!;
    const canonicalAttestation = await createSignedAttestation(claimed, canonical, PRIVATE_KEY, { createAttestationId: () => "canonical_attestation", now: () => FIXED_TIME });
    const canonicalRejected = await post("/v1/attestations", {
      jobId: claimed.jobId,
      report: canonical,
      attestation: canonicalAttestation,
      transactionHash: `0x${"33".repeat(32)}`,
    }, validatorToken, "canonical-attestation");
    expect(canonicalRejected.status).toBe(422);
    expect((await canonicalRejected.json() as { type: string }).type).toContain("non-independent-report");
    const wrongSignature = await post("/v1/attestations", {
      jobId: claimed.jobId,
      report: independent,
      attestation: { ...attestation, signature: `0x${"11".repeat(65)}` },
      transactionHash: `0x${"34".repeat(32)}`,
    }, validatorToken, "wrong-signature");
    expect([403, 422]).toContain(wrongSignature.status);
    const submitted = await post("/v1/attestations", {
      jobId: claimed.jobId,
      report: independent,
      attestation,
      transactionHash: `0x${"44".repeat(32)}`,
    }, validatorToken, "attestation");
    expect(submitted.status).toBe(202);
    const publicResult = await app.handle(new Request(`http://dadieng.local/v1/attestations/${attestation.attestationId}`));
    expect(publicResult.status).toBe(200);
    expect((await publicResult.json() as { report: { reportHash: string } }).report.reportHash).toBe(independent.reportHash);
  });

  it("rejects the canonical report and a signature from a different validator wallet", async () => {
    const claimed = job();
    const report = runIndependentReplay(claimed, { replay: replayRuntime("independent_run_3"), createAttestationId: () => "att_3", now: () => FIXED_TIME });
    const attestation = await createSignedAttestation(claimed, report, PRIVATE_KEY, { createAttestationId: () => "att_3", now: () => FIXED_TIME });
    expect(await verifyAttestationSignature(attestation, privateKeyToAccount(OTHER_PRIVATE_KEY).address)).toBe(false);
  });
});
