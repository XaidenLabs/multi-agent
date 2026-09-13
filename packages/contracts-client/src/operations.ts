import type { Hex } from "viem";

export type ChainOperationRequest =
  | {
      kind: "register-defense";
      defenseId: string;
      authorAgentId: string;
    }
  | {
      kind: "publish-version";
      defenseId: string;
      version: string;
      manifestHash: Hex;
      artifactHash: Hex;
      manifestURI: string;
      supersedes: Hex;
    }
  | {
      kind: "publish-replay";
      versionKey: Hex;
      reportHash: Hex;
      reportURI: string;
      attackPassed: number;
      attackTotal: number;
      controlPassed: number;
      controlTotal: number;
    }
  | {
      kind: "publish-receipt";
      receiptId: string;
      receiptHash: Hex;
      evidenceHash: Hex;
      attackClass: string;
      reporterAgentId: string;
    }
  | {
      kind: "submit-attestation";
      versionKey: Hex;
      passed: boolean;
      reportHash: Hex;
      reportURI: string;
      attackPassed: number;
      attackTotal: number;
      controlPassed: number;
      controlTotal: number;
    }
  | { kind: "promote-version"; versionKey: Hex }
  | {
      kind: "quarantine-version" | "revoke-version";
      versionKey: Hex;
      reasonCode: string;
      evidenceHash: Hex;
      replacementVersionKey: Hex;
    }
  | {
      kind: "commit-usage-batch";
      epoch: string;
      adopterAgentId: string;
      versionKey: Hex;
      root: Hex;
      count: string;
    };

export type ChainOperationStatus = "queued" | "prepared" | "submitted" | "confirmed" | "failed";

export interface ChainOperationRecord {
  operationId: string;
  deduplicationKey: string;
  tenantId: string;
  request: ChainOperationRequest;
  status: ChainOperationStatus;
  attempts: number;
  nextAttemptAt: string;
  preparedTransactionHash?: Hex;
  serializedTransaction?: Hex;
  transactionHash?: Hex;
  blockNumber?: string;
  confirmations?: number;
  errorCode?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ClaimedChainOperation {
  operation: ChainOperationRecord;
  claimToken: string;
}

export interface ChainOperationRepository {
  enqueueChainOperation(record: ChainOperationRecord): Promise<{ created: boolean; operation: ChainOperationRecord }>;
  getChainOperation(operationId: string): Promise<ChainOperationRecord | undefined>;
  claimNextChainOperation(now: string, claimExpiresAt: string): Promise<ClaimedChainOperation | undefined>;
  updateClaimedChainOperation(operation: ChainOperationRecord, claimToken: string): Promise<void>;
}
