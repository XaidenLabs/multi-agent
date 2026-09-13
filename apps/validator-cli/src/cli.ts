#!/usr/bin/env node
import { homedir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  ChainOperationCoordinator,
  createViemMonadTransactionAdapter,
  sha256Commitment,
  type ChainOperationRecord,
} from "@dadieng/contracts-client";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import type { ReplayReport, ValidatorAttestation } from "@dadieng/schemas";
import { ValidatorApiClient } from "./api.js";
import {
  createSignedAttestation,
  createValidatorChainReader,
  runIndependentReplay,
  verifyValidationJob,
} from "./index.js";
import { ValidatorWorkspace } from "./storage.js";

const workspace = new ValidatorWorkspace(process.env.DADIENG_VALIDATOR_HOME ?? join(homedir(), ".config", "dadieng-validator"));

function option(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function required(value: string | undefined, message: string): string {
  if (!value) throw new Error(message);
  return value;
}

async function api(): Promise<ValidatorApiClient> {
  return new ValidatorApiClient(await workspace.loadCredentials());
}

async function login() {
  const apiUrl = required(option("--api"), "login requires --api <url>");
  const token = required(option("--token") ?? process.env.DADIENG_API_KEY, "login requires --token or DADIENG_API_KEY");
  await workspace.saveCredentials({ apiUrl, token });
  console.log(JSON.stringify({ status: "authenticated", apiUrl }));
}

async function listJobs() {
  const jobs = await (await api()).listJobs();
  console.log(JSON.stringify({ jobs: jobs.map(({ bundle: _bundle, ...job }) => job) }, null, 2));
}

async function claimJob(jobId: string) {
  const job = await (await api()).claimJob(jobId);
  await workspace.saveJob(job);
  console.log(JSON.stringify({ jobId, status: job.status, claimExpiresAt: job.claimExpiresAt }));
}

async function verifyJob(jobId: string) {
  const job = await workspace.getJob(jobId);
  if (!job) throw new Error("Claim the validation job before verifying it");
  const rpcUrl = required(process.env.MONAD_RPC_URL, "MONAD_RPC_URL is required");
  await verifyValidationJob(job, createValidatorChainReader(rpcUrl, job.chainId));
  const report = runIndependentReplay(job);
  await workspace.saveReport(jobId, report);
  console.log(JSON.stringify({ jobId, status: "verified", reportHash: report.reportHash, passed: report.releaseEligible }));
}

async function attestJob(jobId: string) {
  const job = await workspace.getJob(jobId);
  const report = await workspace.getReport(jobId);
  if (!job || !report) throw new Error("Verify the claimed job before attesting it");
  const privateKey = required(process.env.MONAD_PRIVATE_KEY, "MONAD_PRIVATE_KEY is required") as Hex;
  const account = privateKeyToAccount(privateKey);
  if (!job.validatorAddress || account.address.toLowerCase() !== job.validatorAddress.toLowerCase()) {
    throw new Error("MONAD_PRIVATE_KEY does not match the claimed validator wallet");
  }
  let attestation = await workspace.getAttestation(jobId);
  if (!attestation) {
    attestation = await createSignedAttestation(job, report, privateKey);
    await workspace.saveAttestation(jobId, attestation);
  }
  const rpcUrl = required(process.env.MONAD_RPC_URL, "MONAD_RPC_URL is required");
  const rewards = required(process.env.DADIENG_REWARDS_ADDRESS, "DADIENG_REWARDS_ADDRESS is required") as `0x${string}`;
  const adapter = createViemMonadTransactionAdapter({
    rpcUrl,
    privateKey,
    chainId: job.chainId,
    registry: job.registryAddress as `0x${string}`,
    validation: job.validationAddress as `0x${string}`,
    rewards,
    requiredConfirmations: Number(process.env.DADIENG_CHAIN_CONFIRMATIONS ?? "2"),
  });
  const coordinator = new ChainOperationCoordinator(
    workspace,
    adapter,
    { createId: randomUUID, now: () => new Date().toISOString() },
    0,
  );
  let operation = (await coordinator.enqueue({
    tenantId: "validator-local",
    deduplicationKey: `attestation:${attestation.attestationId}:${attestation.reportHash}`,
    request: {
      kind: "submit-attestation",
      versionKey: job.versionKey as Hex,
      passed: attestation.passed,
      reportHash: sha256Commitment(attestation.reportHash),
      reportURI: `${(await workspace.loadCredentials()).apiUrl.replace(/\/$/, "")}/v1/attestations/${attestation.attestationId}`,
      attackPassed: report.summary.attack.passed,
      attackTotal: report.summary.attack.total,
      controlPassed: report.summary.control.passed,
      controlTotal: report.summary.control.total,
    },
  })).operation;
  for (let step = 0; step < 3 && operation.status !== "confirmed" && operation.status !== "failed"; step += 1) {
    operation = (await coordinator.runNext()) ?? operation;
  }
  await finishAttestation(jobId, report, attestation, operation);
}

async function finishAttestation(
  jobId: string,
  report: ReplayReport,
  attestation: ValidatorAttestation,
  operation: ChainOperationRecord,
) {
  if (operation.status === "failed") throw new Error(`Monad attestation failed: ${operation.errorCode ?? "UNKNOWN"}`);
  if (operation.status === "confirmed" && operation.transactionHash) {
    await (await api()).submitAttestation({ jobId, report, attestation, transactionHash: operation.transactionHash });
  }
  console.log(JSON.stringify({
    jobId,
    status: operation.status,
    operationId: operation.operationId,
    transactionHash: operation.transactionHash ?? operation.preparedTransactionHash ?? null,
    confirmations: operation.confirmations ?? 0,
    retrySafe: operation.status !== "confirmed",
  }));
}

async function main() {
  const [command, subcommand, identifier] = process.argv.slice(2);
  if (command === "login") return login();
  if (command === "jobs" && subcommand === "list") return listJobs();
  if (command === "jobs" && subcommand === "claim" && identifier) return claimJob(identifier);
  if (command === "verify" && subcommand) return verifyJob(subcommand);
  if (command === "attest" && subcommand) return attestJob(subcommand);
  throw new Error("Usage: dadieng-validator login|jobs list|jobs claim <job-id>|verify <job-id>|attest <job-id>");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Validator command failed");
  process.exitCode = 1;
});
