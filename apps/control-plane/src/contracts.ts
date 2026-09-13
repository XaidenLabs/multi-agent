import { z } from "zod";
import {
  defenseArtifactSchema,
  defenseManifestSchema,
  defenseSbomSchema,
  defenseTestSuiteSchema,
  encryptedThreatEvidenceSchema,
  publicIdentifierSchema,
  replayEnvironmentSchema,
  replayReportSchema,
  threatReceiptSchema,
  validatorAttestationSchema,
} from "@dadieng/schemas";

export const createReceiptRequestSchema = z.object({
  receipt: threatReceiptSchema,
  encryptedEvidence: encryptedThreatEvidenceSchema,
  publishCommitment: z.boolean().default(false),
});

export const createDefenseRequestSchema = z.object({
  defenseId: publicIdentifierSchema,
  name: z.string().min(1).max(160),
  authorAgentId: publicIdentifierSchema,
});

export const defenseBundleSchema = z.object({
  manifest: defenseManifestSchema,
  artifact: defenseArtifactSchema,
  suite: defenseTestSuiteSchema,
  sbom: defenseSbomSchema,
});

export const createDefenseVersionRequestSchema = z.object({
  bundle: defenseBundleSchema,
});

export const quarantineDefenseVersionRequestSchema = z.object({
  reasonCode: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/),
  evidenceHash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  replacementDefenseVersionId: z.string().regex(/^[A-Za-z0-9._:-]+@\d+\.\d+\.\d+$/).nullable().default(null),
});

export const createReplayRequestSchema = z.object({
  defenseVersionId: z.string().regex(/^[A-Za-z0-9._:-]+@\d+\.\d+\.\d+$/),
  environment: replayEnvironmentSchema,
  thresholds: z.object({
    attackPassRate: z.number().min(0).max(1).optional(),
    controlPassRate: z.number().min(0).max(1).optional(),
    p95LatencyMs: z.number().nonnegative().optional(),
  }).optional(),
});

export const claimValidationJobRequestSchema = z.object({}).strict();

export const submitValidatorAttestationRequestSchema = z.object({
  jobId: publicIdentifierSchema,
  report: replayReportSchema,
  attestation: validatorAttestationSchema,
  transactionHash: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
});

export const creValidationCycleRequestSchema = z.object({
  network: z.literal("monad-testnet"),
  coordinator: z.literal("chainlink-cre"),
}).strict();

export const creValidationCycleReceiptSchema = z.object({
  cycleId: publicIdentifierSchema,
  status: z.enum(["idle", "replaying", "awaiting-attestations", "submitted"]),
  reportHashes: z.array(z.string().regex(/^sha256:[a-f0-9]{64}$/)).max(32),
});

export type CreateReceiptRequest = z.infer<typeof createReceiptRequestSchema>;
export type CreateDefenseRequest = z.infer<typeof createDefenseRequestSchema>;
export type CreateDefenseVersionRequest = z.infer<typeof createDefenseVersionRequestSchema>;
export type QuarantineDefenseVersionRequest = z.infer<typeof quarantineDefenseVersionRequestSchema>;
export type CreateReplayRequest = z.infer<typeof createReplayRequestSchema>;
export type ClaimValidationJobRequest = z.infer<typeof claimValidationJobRequestSchema>;
export type SubmitValidatorAttestationRequest = z.infer<typeof submitValidatorAttestationRequestSchema>;
export type CreValidationCycleRequest = z.infer<typeof creValidationCycleRequestSchema>;
export type CreValidationCycleReceipt = z.infer<typeof creValidationCycleReceiptSchema>;
