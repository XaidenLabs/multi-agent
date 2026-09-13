import { indexer } from "envio";

const METRICS_ID = "dadieng";
const metricsDefaults = {
  id: METRICS_ID,
  defenseCount: 0,
  versionCount: 0,
  stableVersionCount: 0,
  quarantinedVersionCount: 0,
  receiptCount: 0,
  attestationCount: 0,
  passingAttestationCount: 0,
  protectedEventCount: 0n,
  rewardClaimed: 0n,
  validatorThreshold: 0,
  lastIndexedBlock: 0n,
  lastIndexedAt: 0n,
};

const eventId = (event: { transaction: { hash: string }; logIndex: number }) =>
  `${event.transaction.hash.toLowerCase()}:${event.logIndex}`;

indexer.onEvent({ contract: "DadiengRegistry", event: "DefenseRegistered" }, async ({ event, context }) => {
  const metrics = await context.ProtocolMetrics.get(METRICS_ID) ?? metricsDefaults;
  context.Defense.set({
    id: event.params.defenseId,
    authorAgentId: event.params.authorAgentId,
    registeredAt: BigInt(event.block.timestamp),
    transactionHash: event.transaction.hash,
  });
  context.ProtocolMetrics.set({ ...metrics, defenseCount: metrics.defenseCount + 1, lastIndexedBlock: BigInt(event.block.number), lastIndexedAt: BigInt(event.block.timestamp) });
});

indexer.onEvent({ contract: "DadiengRegistry", event: "DefenseVersionPublished" }, async ({ event, context }) => {
  const metrics = await context.ProtocolMetrics.get(METRICS_ID) ?? metricsDefaults;
  context.DefenseVersion.set({
    id: event.params.versionKey,
    defense_id: event.params.defenseId,
    status: Number(event.params.status),
    replayReportHash: undefined,
    validationFinal: false,
    passingAttestations: 0,
    validationThreshold: 0,
    publishedAt: BigInt(event.block.timestamp),
    updatedAt: BigInt(event.block.timestamp),
    transactionHash: event.transaction.hash,
  });
  context.ProtocolMetrics.set({ ...metrics, versionCount: metrics.versionCount + 1, lastIndexedBlock: BigInt(event.block.number), lastIndexedAt: BigInt(event.block.timestamp) });
});

indexer.onEvent({ contract: "DadiengRegistry", event: "ReplayBundlePublished" }, async ({ event, context }) => {
  const version = await context.DefenseVersion.getOrThrow(event.params.versionKey);
  context.DefenseVersion.set({ ...version, replayReportHash: event.params.reportHash, updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});

indexer.onEvent({ contract: "DadiengRegistry", event: "VersionStatusChanged" }, async ({ event, context }) => {
  const [version, metrics] = await Promise.all([
    context.DefenseVersion.getOrThrow(event.params.versionKey),
    context.ProtocolMetrics.get(METRICS_ID),
  ]);
  const current = metrics ?? metricsDefaults;
  context.DefenseVersion.set({ ...version, status: Number(event.params.newStatus), updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
  context.ProtocolMetrics.set({
    ...current,
    stableVersionCount: current.stableVersionCount + Number(event.params.newStatus === 3n) - Number(event.params.oldStatus === 3n),
    quarantinedVersionCount: current.quarantinedVersionCount + Number(event.params.newStatus === 4n) - Number(event.params.oldStatus === 4n),
    lastIndexedBlock: BigInt(event.block.number),
    lastIndexedAt: BigInt(event.block.timestamp),
  });
});

indexer.onEvent({ contract: "DadiengRegistry", event: "VersionSafetyAction" }, async ({ event, context }) => {
  context.SafetyAction.set({
    id: eventId(event),
    version_id: event.params.versionKey,
    reasonCode: event.params.reasonCode,
    evidenceHash: event.params.evidenceHash,
    actor: event.params.actor,
    replacementVersionKey: event.params.replacementVersionKey,
    timestamp: event.params.timestamp,
    transactionHash: event.transaction.hash,
  });
});

indexer.onEvent({ contract: "DadiengRegistry", event: "ThreatReceiptPublished" }, async ({ event, context }) => {
  const metrics = await context.ProtocolMetrics.get(METRICS_ID) ?? metricsDefaults;
  context.ThreatReceipt.set({
    id: event.params.receiptId,
    attackClass: event.params.attackClass,
    reporterAgentId: event.params.reporterAgentId,
    linkedVersionKey: undefined,
    resolution: 0,
    publishedAt: BigInt(event.block.timestamp),
    updatedAt: BigInt(event.block.timestamp),
    transactionHash: event.transaction.hash,
  });
  context.ProtocolMetrics.set({ ...metrics, receiptCount: metrics.receiptCount + 1, lastIndexedBlock: BigInt(event.block.number), lastIndexedAt: BigInt(event.block.timestamp) });
});

indexer.onEvent({ contract: "DadiengRegistry", event: "ThreatReceiptLinked" }, async ({ event, context }) => {
  const receipt = await context.ThreatReceipt.getOrThrow(event.params.receiptId);
  context.ThreatReceipt.set({ ...receipt, linkedVersionKey: event.params.versionKey, updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});

indexer.onEvent({ contract: "DadiengRegistry", event: "ThreatReceiptResolutionChanged" }, async ({ event, context }) => {
  const receipt = await context.ThreatReceipt.getOrThrow(event.params.receiptId);
  context.ThreatReceipt.set({ ...receipt, resolution: Number(event.params.newResolution), updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});

indexer.onEvent({ contract: "DadiengValidation", event: "ValidatorIdentitySet" }, async ({ event, context }) => {
  const validator = await context.Validator.get(event.params.agentId.toString());
  context.Validator.set({
    id: event.params.agentId.toString(),
    wallet: event.params.validator,
    active: event.params.active,
    submittedCount: validator?.submittedCount ?? 0,
    passingCount: validator?.passingCount ?? 0,
    challengedCount: validator?.challengedCount ?? 0,
    updatedAt: BigInt(event.block.timestamp),
  });
});

indexer.onEvent({ contract: "DadiengValidation", event: "AttestationSubmitted" }, async ({ event, context }) => {
  const validatorId = event.params.validatorAgentId.toString();
  const [validator, metrics] = await Promise.all([
    context.Validator.getOrThrow(validatorId),
    context.ProtocolMetrics.get(METRICS_ID),
  ]);
  context.Attestation.set({
    id: `${event.params.versionKey}:${validatorId}`,
    version_id: event.params.versionKey,
    validator_id: validatorId,
    passed: event.params.passed,
    challenged: false,
    challengeReasonCode: undefined,
    challengeEvidenceHash: undefined,
    submittedAt: BigInt(event.block.timestamp),
    transactionHash: event.transaction.hash,
  });
  context.Validator.set({ ...validator, submittedCount: validator.submittedCount + 1, passingCount: validator.passingCount + Number(event.params.passed), updatedAt: BigInt(event.block.timestamp) });
  const current = metrics ?? metricsDefaults;
  context.ProtocolMetrics.set({ ...current, attestationCount: current.attestationCount + 1, passingAttestationCount: current.passingAttestationCount + Number(event.params.passed), lastIndexedBlock: BigInt(event.block.number), lastIndexedAt: BigInt(event.block.timestamp) });
});

indexer.onEvent({ contract: "DadiengValidation", event: "AttestationChallenged" }, async ({ event, context }) => {
  const validatorId = event.params.validatorAgentId.toString();
  const [attestation, validator] = await Promise.all([
    context.Attestation.getOrThrow(`${event.params.versionKey}:${validatorId}`),
    context.Validator.getOrThrow(validatorId),
  ]);
  context.Attestation.set({ ...attestation, challenged: true, challengeReasonCode: event.params.reasonCode, challengeEvidenceHash: event.params.evidenceHash });
  context.Validator.set({ ...validator, challengedCount: validator.challengedCount + 1, updatedAt: BigInt(event.block.timestamp) });
});

indexer.onEvent({ contract: "DadiengValidation", event: "ValidationFinalized" }, async ({ event, context }) => {
  const version = await context.DefenseVersion.getOrThrow(event.params.versionKey);
  context.DefenseVersion.set({ ...version, validationFinal: true, passingAttestations: Number(event.params.passingAttestations), validationThreshold: Number(event.params.threshold), updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});

indexer.onEvent({ contract: "DadiengValidation", event: "ValidatorThresholdChanged" }, async ({ event, context }) => {
  const metrics = await context.ProtocolMetrics.get(METRICS_ID) ?? metricsDefaults;
  context.ProtocolMetrics.set({ ...metrics, validatorThreshold: Number(event.params.newThreshold), lastIndexedBlock: BigInt(event.block.number), lastIndexedAt: BigInt(event.block.timestamp) });
});

indexer.onEvent({ contract: "DadiengRewards", event: "UsageBatchCommitted" }, async ({ event, context }) => {
  context.UsageCommitment.set({ id: event.params.root, epoch: event.params.epoch, adopterAgentId: event.params.adopterId, root: event.params.root, committedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});

indexer.onEvent({ contract: "DadiengRewards", event: "UsageBatchRecorded" }, async ({ event, context }) => {
  const metrics = await context.ProtocolMetrics.get(METRICS_ID) ?? metricsDefaults;
  context.UsageBatch.set({ id: event.params.batchId, versionKey: event.params.versionKey, count: event.params.count, committer: event.params.committer, challenged: false, finalized: false, reasonCode: undefined, evidenceHash: undefined, rewardAllocated: 0n, recordedAt: BigInt(event.block.timestamp), updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
  context.ProtocolMetrics.set({ ...metrics, protectedEventCount: metrics.protectedEventCount + event.params.count, lastIndexedBlock: BigInt(event.block.number), lastIndexedAt: BigInt(event.block.timestamp) });
});

indexer.onEvent({ contract: "DadiengRewards", event: "UsageBatchChallenged" }, async ({ event, context }) => {
  const batch = await context.UsageBatch.getOrThrow(event.params.batchId);
  context.UsageBatch.set({ ...batch, challenged: true, reasonCode: event.params.reasonCode, evidenceHash: event.params.evidenceHash, updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});

indexer.onEvent({ contract: "DadiengRewards", event: "UsageBatchFinalized" }, async ({ event, context }) => {
  const batch = await context.UsageBatch.getOrThrow(event.params.batchId);
  context.UsageBatch.set({ ...batch, finalized: true, updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});

indexer.onEvent({ contract: "DadiengRewards", event: "RewardsAllocated" }, async ({ event, context }) => {
  const batch = await context.UsageBatch.getOrThrow(event.params.batchId);
  context.UsageBatch.set({ ...batch, rewardAllocated: event.params.totalAmount, updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});

indexer.onEvent({ contract: "DadiengRewards", event: "RewardClaimed" }, async ({ event, context }) => {
  const metrics = await context.ProtocolMetrics.get(METRICS_ID) ?? metricsDefaults;
  context.RewardClaim.set({ id: eventId(event), epoch: event.params.epoch, recipient: event.params.recipient, amount: event.params.amount, claimedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
  context.ProtocolMetrics.set({ ...metrics, rewardClaimed: metrics.rewardClaimed + event.params.amount, lastIndexedBlock: BigInt(event.block.number), lastIndexedAt: BigInt(event.block.timestamp) });
});

indexer.onEvent({ contract: "DadiengRegistry", event: "RegistryProtocolPaused" }, async ({ event, context }) => {
  context.PauseState.set({ id: `DadiengRegistry:${event.params.scope}`, contract: "DadiengRegistry", scope: event.params.scope, actor: event.params.actor, paused: event.params.paused, reasonCode: event.params.reasonCode, expiresAt: event.params.expiresAt, updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});

indexer.onEvent({ contract: "DadiengRewards", event: "RewardsProtocolPaused" }, async ({ event, context }) => {
  context.PauseState.set({ id: `DadiengRewards:${event.params.scope}`, contract: "DadiengRewards", scope: event.params.scope, actor: event.params.actor, paused: event.params.paused, reasonCode: event.params.reasonCode, expiresAt: event.params.expiresAt, updatedAt: BigInt(event.block.timestamp), transactionHash: event.transaction.hash });
});
