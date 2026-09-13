import { randomUUID } from "node:crypto";
import { defenseVersionKey, sha256Commitment } from "@dadieng/contracts-client";
import { verifyDefenseBundle, type DefenseBundle, type VerifiedDefenseBundle } from "@dadieng/defense-module";
import { runReplay, verifyReplayReport, type ReplayRuntime } from "@dadieng/replay-engine";
import {
  DADIENG_ATTESTATION_SCHEMA_VERSION,
  replayEnvironmentSchema,
  validatorAttestationSchema,
  validatorAttestationSigningMessage,
  type ReplayReport,
  type ValidatorAttestation,
} from "@dadieng/schemas";
import {
  createPublicClient,
  defineChain,
  getAddress,
  http,
  isAddressEqual,
  parseAbi,
  recoverMessageAddress,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { z } from "zod";

const hash256Schema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const hex32Schema = z.string().regex(/^0x[a-fA-F0-9]{64}$/);
const addressSchema = z.string().regex(/^0x[a-fA-F0-9]{40}$/);

export const validationJobSchema = z.object({
  jobId: z.string().min(1),
  defenseVersionId: z.string().min(1),
  versionKey: hex32Schema,
  chainId: z.number().int().positive(),
  registryAddress: addressSchema,
  validationAddress: addressSchema,
  bundle: z.object({
    manifest: z.unknown(),
    artifact: z.unknown(),
    suite: z.unknown(),
    sbom: z.unknown(),
  }),
  environment: replayEnvironmentSchema,
  thresholds: z.object({
    attackPassRate: z.number().min(0).max(1).optional(),
    controlPassRate: z.number().min(0).max(1).optional(),
    p95LatencyMs: z.number().nonnegative().optional(),
  }).optional(),
  status: z.enum(["open", "claimed", "submitted"]),
  validatorAgentId: z.string().regex(/^[1-9]\d*$/).optional(),
  validatorAddress: addressSchema.optional(),
  claimExpiresAt: z.string().datetime({ offset: true }).optional(),
});

export type ValidationJob = Omit<z.infer<typeof validationJobSchema>, "bundle"> & { bundle: DefenseBundle };

export interface OnchainVersionCommitment {
  status: number;
  manifestHash: Hex;
  artifactHash: Hex;
  authorAgentId: bigint;
}

export interface ValidatorChainReader {
  getCode(address: Address): Promise<Hex | undefined>;
  getVersion(registry: Address, versionKey: Hex): Promise<OnchainVersionCommitment>;
  getValidatorAgentId(validation: Address, validator: Address): Promise<bigint>;
}

const registryAbi = parseAbi([
  "function getVersion(bytes32 key) view returns ((bytes32 defenseId,uint64 major,uint64 minor,uint64 patch,bytes32 manifestHash,bytes32 artifactHash,string manifestURI,uint256 authorAgentId,uint8 status,uint64 createdAt,bytes32 supersedes,bytes32 replayReportHash,string replayReportURI,uint32 attackPassed,uint32 attackTotal,uint32 controlPassed,uint32 controlTotal))",
]);
const validationAbi = parseAbi([
  "function validatorAgentIds(address validator) view returns (uint256)",
]);

export function createValidatorChainReader(rpcUrl: string, chainId: number): ValidatorChainReader {
  if (!/^https?:\/\//.test(rpcUrl)) throw new Error("MONAD_RPC_URL must use HTTP or HTTPS");
  const chain = defineChain({
    id: chainId,
    name: chainId === 10_143 ? "Monad Testnet" : `Dadieng chain ${chainId}`,
    nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
  const client = createPublicClient({ chain, transport: http(rpcUrl, { retryCount: 0, timeout: 10_000 }) });
  return {
    getCode: (address) => client.getCode({ address }),
    async getVersion(registry, versionKey) {
      const version = await client.readContract({ address: registry, abi: registryAbi, functionName: "getVersion", args: [versionKey] });
      return {
        status: version.status,
        manifestHash: version.manifestHash,
        artifactHash: version.artifactHash,
        authorAgentId: version.authorAgentId,
      };
    },
    getValidatorAgentId: (validation, validator) => client.readContract({
      address: validation,
      abi: validationAbi,
      functionName: "validatorAgentIds",
      args: [validator],
    }),
  };
}

export async function verifyValidationJob(
  input: unknown,
  reader: ValidatorChainReader,
  now: () => string = () => new Date().toISOString(),
): Promise<{ job: ValidationJob; bundle: VerifiedDefenseBundle }> {
  const parsed = validationJobSchema.parse(input);
  if (parsed.status !== "claimed" || !parsed.validatorAgentId || !parsed.validatorAddress) {
    throw new Error("Validation job must be claimed before verification");
  }
  const job = parsed as ValidationJob;
  if (!job.claimExpiresAt || job.claimExpiresAt <= now()) throw new Error("Validation job claim has expired");
  const bundle = verifyDefenseBundle(job.bundle);
  if (`${bundle.manifest.defenseId}@${bundle.manifest.version}` !== job.defenseVersionId) {
    throw new Error("Validation job defense version does not match its bundle");
  }
  if (defenseVersionKey(bundle.manifest.defenseId, bundle.manifest.version).toLowerCase() !== job.versionKey.toLowerCase()) {
    throw new Error("Validation job version key mismatch");
  }
  const registryAddress = getAddress(job.registryAddress);
  const validationAddress = getAddress(job.validationAddress);
  const validatorAddress = getAddress(job.validatorAddress!);
  const [registryCode, validationCode, version, registeredAgentId] = await Promise.all([
    reader.getCode(registryAddress),
    reader.getCode(validationAddress),
    reader.getVersion(registryAddress, job.versionKey as Hex),
    reader.getValidatorAgentId(validationAddress, validatorAddress),
  ]);
  if (!registryCode || registryCode === "0x" || !validationCode || validationCode === "0x") {
    throw new Error("Dadieng contracts are not deployed at the validation job addresses");
  }
  if (version.status !== 2) throw new Error("Defense version is not a Monad candidate");
  if (version.manifestHash.toLowerCase() !== sha256Commitment(bundle.manifestHash).toLowerCase()
    || version.artifactHash.toLowerCase() !== sha256Commitment(bundle.manifest.artifactHash).toLowerCase()) {
    throw new Error("Monad commitment does not match the downloaded defense bundle");
  }
  if (registeredAgentId.toString() !== job.validatorAgentId) throw new Error("Validator wallet is not bound to the claimed ERC-8004 identity");
  if (version.authorAgentId === registeredAgentId) throw new Error("Defense authors cannot attest to their own versions");
  return { job, bundle };
}

export interface IndependentReplayRuntime {
  replay?: ReplayRuntime;
  createAttestationId(): string;
  now(): string;
}

const defaultRuntime: IndependentReplayRuntime = {
  createAttestationId: randomUUID,
  now: () => new Date().toISOString(),
};

export function runIndependentReplay(
  job: ValidationJob,
  runtime: IndependentReplayRuntime = defaultRuntime,
): ReplayReport {
  const report = runReplay(job.bundle, {
    environment: job.environment,
    ...(job.thresholds ? { thresholds: {
      ...(job.thresholds.attackPassRate !== undefined ? { attackPassRate: job.thresholds.attackPassRate } : {}),
      ...(job.thresholds.controlPassRate !== undefined ? { controlPassRate: job.thresholds.controlPassRate } : {}),
      ...(job.thresholds.p95LatencyMs !== undefined ? { p95LatencyMs: job.thresholds.p95LatencyMs } : {}),
    } } : {}),
    ...(runtime.replay ? { runtime: runtime.replay } : {}),
  });
  return verifyReplayReport(report, job.bundle);
}

export async function createSignedAttestation(
  job: ValidationJob,
  reportInput: ReplayReport,
  privateKey: Hex,
  runtime: IndependentReplayRuntime = defaultRuntime,
): Promise<ValidatorAttestation> {
  if (!job.validatorAgentId || !job.validatorAddress) throw new Error("Validation job has no claimed validator identity");
  const report = verifyReplayReport(reportInput, job.bundle);
  const account = privateKeyToAccount(privateKey);
  if (!isAddressEqual(account.address, getAddress(job.validatorAddress))) {
    throw new Error("Monad private key does not match the claimed validator wallet");
  }
  const unsigned: Omit<ValidatorAttestation, "signature"> = {
    schemaVersion: DADIENG_ATTESTATION_SCHEMA_VERSION,
    attestationId: runtime.createAttestationId(),
    validatorAgentId: job.validatorAgentId,
    chainId: job.chainId,
    registryAddress: getAddress(job.registryAddress),
    defenseVersionId: job.defenseVersionId,
    artifactHash: job.bundle.manifest.artifactHash,
    suiteHash: job.bundle.manifest.suiteHash,
    reportHash: report.reportHash,
    passed: report.releaseEligible,
    signedAt: runtime.now(),
  };
  const signature = await account.signMessage({ message: validatorAttestationSigningMessage(unsigned) });
  return validatorAttestationSchema.parse({ ...unsigned, signature });
}

export async function verifyAttestationSignature(attestation: ValidatorAttestation, expectedAddress: Address): Promise<boolean> {
  const { signature, ...unsigned } = validatorAttestationSchema.parse(attestation);
  const recovered = await recoverMessageAddress({
    message: validatorAttestationSigningMessage(unsigned),
    signature: signature as Hex,
  });
  return isAddressEqual(recovered, expectedAddress);
}

export const validatorCommitmentSchema = z.object({
  reportHash: hash256Schema,
  attestation: validatorAttestationSchema,
});
