export type VersionStatus = 0 | 1 | 2 | 3 | 4 | 5;

export interface IndexerMetrics {
  defenseCount: number;
  versionCount: number;
  stableVersionCount: number;
  quarantinedVersionCount: number;
  receiptCount: number;
  attestationCount: number;
  passingAttestationCount: number;
  protectedEventCount: bigint;
  rewardClaimed: bigint;
  validatorThreshold: number;
  lastIndexedBlock: bigint;
  lastIndexedAt: bigint;
}

export const emptyMetrics = (): IndexerMetrics => ({
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
});

export function transitionVersionMetrics(
  metrics: IndexerMetrics,
  oldStatus: VersionStatus,
  newStatus: VersionStatus,
): IndexerMetrics {
  if (oldStatus === newStatus) return metrics;
  return {
    ...metrics,
    stableVersionCount: metrics.stableVersionCount + Number(newStatus === 3) - Number(oldStatus === 3),
    quarantinedVersionCount: metrics.quarantinedVersionCount + Number(newStatus === 4) - Number(oldStatus === 4),
  };
}

export function freshness(lastIndexedAt: bigint, nowSeconds: bigint, staleAfterSeconds = 15n) {
  const ageSeconds = nowSeconds > lastIndexedAt ? nowSeconds - lastIndexedAt : 0n;
  return { ageSeconds, stale: lastIndexedAt === 0n || ageSeconds > staleAfterSeconds };
}

export function eventId(transactionHash: string, logIndex: number): string {
  return `${transactionHash.toLowerCase()}:${logIndex}`;
}
