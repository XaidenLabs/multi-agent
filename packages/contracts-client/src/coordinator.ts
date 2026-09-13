import type { Hash, Hex } from "viem";
import { ChainAdapterError, type MonadTransactionAdapter, type PreparedChainTransaction } from "./adapter.js";
import type { ChainOperationRecord, ChainOperationRepository, ChainOperationRequest } from "./operations.js";

export interface ChainCoordinatorRuntime {
  createId(): string;
  now(): string;
}

export interface EnqueueChainOperationInput {
  tenantId: string;
  deduplicationKey: string;
  request: ChainOperationRequest;
}

export class ChainOperationCoordinator {
  constructor(
    readonly repository: ChainOperationRepository,
    private readonly adapter: MonadTransactionAdapter,
    private readonly runtime: ChainCoordinatorRuntime,
    private readonly retryDelayMs = 5_000,
    private readonly claimLeaseMs = 30_000,
  ) {}

  async enqueue(input: EnqueueChainOperationInput): Promise<{ created: boolean; operation: ChainOperationRecord }> {
    const now = this.runtime.now();
    return this.repository.enqueueChainOperation({
      operationId: this.runtime.createId(),
      deduplicationKey: input.deduplicationKey,
      tenantId: input.tenantId,
      request: input.request,
      status: "queued",
      attempts: 0,
      nextAttemptAt: now,
      createdAt: now,
      updatedAt: now,
    });
  }

  async get(operationId: string): Promise<ChainOperationRecord | undefined> {
    return this.repository.getChainOperation(operationId);
  }

  async runNext(): Promise<ChainOperationRecord | undefined> {
    const now = this.runtime.now();
    const lease = new Date(Date.parse(now) + this.claimLeaseMs).toISOString();
    const claim = await this.repository.claimNextChainOperation(now, lease);
    if (!claim) return undefined;
    const operation = claim.operation;
    operation.attempts += 1;
    operation.updatedAt = now;
    delete operation.errorCode;

    try {
      if (operation.status === "queued") {
        const prepared = await this.adapter.prepare(operation.request);
        operation.status = "prepared";
        operation.preparedTransactionHash = prepared.transactionHash;
        operation.serializedTransaction = prepared.serializedTransaction;
      } else if (operation.status === "prepared") {
        const prepared = this.prepared(operation);
        await this.adapter.broadcast(prepared);
        operation.status = "submitted";
        operation.transactionHash = prepared.transactionHash;
      } else if (operation.status === "submitted") {
        if (!operation.transactionHash) throw new ChainAdapterError("MISSING_TRANSACTION_HASH", false);
        const observation = await this.adapter.inspect(operation.transactionHash);
        if (observation.status === "confirmed") {
          operation.status = "confirmed";
          operation.blockNumber = observation.blockNumber.toString();
          operation.confirmations = observation.confirmations;
        } else if (observation.status === "reverted") {
          operation.status = "failed";
          operation.blockNumber = observation.blockNumber.toString();
          operation.errorCode = "TRANSACTION_REVERTED";
        } else if (observation.status === "replaced") {
          operation.transactionHash = observation.transactionHash;
        }
      }
    } catch (error) {
      const adapterError = error instanceof ChainAdapterError
        ? error
        : new ChainAdapterError("CHAIN_ADAPTER_FAILED", false);
      operation.errorCode = adapterError.code;
      if (!adapterError.retryable) operation.status = "failed";
    }

    operation.nextAttemptAt = operation.status === "confirmed" || operation.status === "failed"
      ? now
      : new Date(Date.parse(now) + this.retryDelayMs).toISOString();
    await this.repository.updateClaimedChainOperation(operation, claim.claimToken);
    return operation;
  }

  private prepared(operation: ChainOperationRecord): PreparedChainTransaction {
    if (!operation.preparedTransactionHash || !operation.serializedTransaction) {
      throw new ChainAdapterError("MISSING_PREPARED_TRANSACTION", false);
    }
    return {
      transactionHash: operation.preparedTransactionHash as Hash,
      serializedTransaction: operation.serializedTransaction as Hex,
    };
  }
}
