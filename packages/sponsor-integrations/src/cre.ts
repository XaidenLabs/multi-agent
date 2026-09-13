export interface ReplayProposal {
  id: string;
  attackClass: string;
  fixtureHash: `sha256:${string}`;
}

export interface SignedReplayResult {
  proposalId: string;
  reportHash: `sha256:${string}`;
  releaseEligible: boolean;
  worker: string;
  signature: `0x${string}`;
}

export interface IndependentAttestation {
  validatorId: string;
  reportHash: `sha256:${string}`;
  approved: boolean;
  signature: `0x${string}`;
}

export interface ValidationRequest {
  defenseVersionId: string;
  proposals: ReplayProposal[];
  validatorThreshold: number;
}

export interface ValidationDependencies {
  replay(proposal: ReplayProposal): Promise<SignedReplayResult>;
  attest(result: SignedReplayResult): Promise<IndependentAttestation[]>;
  finalize(input: { defenseVersionId: string; reportHashes: `sha256:${string}`[]; validatorIds: string[] }): Promise<string>;
}

export interface ValidationOutcome {
  status: "finalized" | "rejected";
  reportHashes: `sha256:${string}`[];
  validatorIds: string[];
  operationId?: string;
  reason?: string;
}

export async function runCreValidationWorkflow(
  request: ValidationRequest,
  dependencies: ValidationDependencies,
): Promise<ValidationOutcome> {
  if (!request.defenseVersionId.trim()) throw new Error("CRE validation requires a defense version");
  if (request.proposals.length === 0) throw new Error("CRE validation requires replay proposals");
  if (!Number.isInteger(request.validatorThreshold) || request.validatorThreshold < 2) {
    throw new Error("CRE validation requires at least two independent validators");
  }

  const proposalIds = new Set<string>();
  for (const proposal of request.proposals) {
    if (proposalIds.has(proposal.id)) throw new Error("CRE replay proposal IDs must be unique");
    proposalIds.add(proposal.id);
  }

  const results = await Promise.all(request.proposals.map((proposal) => dependencies.replay(proposal)));
  if (results.some((result, index) => result.proposalId !== request.proposals[index]?.id)) {
    throw new Error("CRE replay result does not match its proposal");
  }
  if (results.some((result) => !result.releaseEligible || !result.signature.startsWith("0x"))) {
    return { status: "rejected", reportHashes: results.map((result) => result.reportHash), validatorIds: [], reason: "Replay assertions failed" };
  }

  const attestations = (await Promise.all(results.map((result) => dependencies.attest(result)))).flat();
  const eligible = new Map<string, IndependentAttestation>();
  const reportHashes = new Set(results.map((result) => result.reportHash));
  for (const attestation of attestations) {
    if (attestation.approved && reportHashes.has(attestation.reportHash) && attestation.signature.startsWith("0x")) {
      eligible.set(attestation.validatorId, attestation);
    }
  }
  const validatorIds = [...eligible.keys()].sort();
  if (validatorIds.length < request.validatorThreshold) {
    return { status: "rejected", reportHashes: [...reportHashes].sort(), validatorIds, reason: "Independent validator threshold not met" };
  }

  const orderedHashes = [...reportHashes].sort();
  const operationId = await dependencies.finalize({ defenseVersionId: request.defenseVersionId, reportHashes: orderedHashes, validatorIds });
  return { status: "finalized", reportHashes: orderedHashes, validatorIds, operationId };
}
