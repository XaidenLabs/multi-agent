import {
  TransactionReceiptNotFoundError,
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  isAddress,
  keccak256,
  type Address,
  type Chain,
  type Hash,
  type Hex,
  type LocalAccount,
  type PublicClient,
  type TransactionReceipt,
  type Transport,
  type WalletClient,
  zeroAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { encodeDadiengOperation, type DadiengContractAddresses } from "./encoding.js";
import type { ChainOperationRequest } from "./operations.js";

export interface PreparedChainTransaction {
  transactionHash: Hash;
  serializedTransaction: Hex;
}

export type ChainTransactionObservation =
  | { status: "pending" }
  | { status: "replaced"; transactionHash: Hash }
  | { status: "confirmed"; blockNumber: bigint; confirmations: number }
  | { status: "reverted"; blockNumber: bigint };

export interface MonadTransactionAdapter {
  prepare(operation: ChainOperationRequest): Promise<PreparedChainTransaction>;
  broadcast(transaction: PreparedChainTransaction): Promise<void>;
  inspect(transactionHash: Hash): Promise<ChainTransactionObservation>;
}

export class ChainAdapterError extends Error {
  constructor(readonly code: string, readonly retryable: boolean) {
    super(code);
  }
}

function safeAdapterError(error: unknown, fallbackCode: string): ChainAdapterError {
  if (error instanceof ChainAdapterError) return error;
  const name = error instanceof Error ? error.name : "";
  const retryable = /timeout|http|socket|network|request|transport/i.test(name);
  return new ChainAdapterError(retryable ? "RPC_UNAVAILABLE" : fallbackCode, retryable);
}

export class ViemMonadTransactionAdapter implements MonadTransactionAdapter {
  constructor(
    private readonly publicClient: PublicClient<Transport, Chain>,
    private readonly walletClient: WalletClient<Transport, Chain, LocalAccount>,
    private readonly account: LocalAccount,
    private readonly addresses: DadiengContractAddresses,
    private readonly requiredConfirmations = 2,
  ) {
    if (!Number.isInteger(requiredConfirmations) || requiredConfirmations < 1) {
      throw new Error("requiredConfirmations must be a positive integer");
    }
  }

  async prepare(operation: ChainOperationRequest): Promise<PreparedChainTransaction> {
    const { to, data } = encodeDadiengOperation(operation, this.addresses);
    try {
      const code = await this.publicClient.getCode({ address: to });
      if (!code || code === "0x") throw new ChainAdapterError("CONTRACT_NOT_DEPLOYED", false);
      await this.publicClient.call({ account: this.account.address, to, data });
      const request = await this.walletClient.prepareTransactionRequest({
        account: this.account,
        chain: this.walletClient.chain,
        to,
        data,
      });
      const serializedTransaction = await this.walletClient.signTransaction(request);
      return { transactionHash: keccak256(serializedTransaction), serializedTransaction };
    } catch (error) {
      throw safeAdapterError(error, "SIMULATION_OR_SIGNING_FAILED");
    }
  }

  async broadcast(transaction: PreparedChainTransaction): Promise<void> {
    try {
      const hash = await this.publicClient.sendRawTransaction({ serializedTransaction: transaction.serializedTransaction });
      if (hash.toLowerCase() !== transaction.transactionHash.toLowerCase()) {
        throw new ChainAdapterError("TRANSACTION_HASH_MISMATCH", false);
      }
    } catch (error) {
      if (error instanceof Error && /already known|known transaction/i.test(error.message)) return;
      throw safeAdapterError(error, "BROADCAST_FAILED");
    }
  }

  async inspect(transactionHash: Hash): Promise<ChainTransactionObservation> {
    let receipt: TransactionReceipt;
    try {
      receipt = await this.publicClient.getTransactionReceipt({ hash: transactionHash });
    } catch (error) {
      if (error instanceof TransactionReceiptNotFoundError) return { status: "pending" };
      throw safeAdapterError(error, "RECEIPT_LOOKUP_FAILED");
    }
    if (receipt.status === "reverted") return { status: "reverted", blockNumber: receipt.blockNumber };
    try {
      const head = await this.publicClient.getBlockNumber();
      const confirmations = Number(head - receipt.blockNumber + 1n);
      return confirmations >= this.requiredConfirmations
        ? { status: "confirmed", blockNumber: receipt.blockNumber, confirmations }
        : { status: "pending" };
    } catch (error) {
      throw safeAdapterError(error, "CONFIRMATION_LOOKUP_FAILED");
    }
  }
}

export interface ViemMonadTransactionAdapterConfig extends DadiengContractAddresses {
  rpcUrl: string;
  privateKey: Hex;
  chainId?: number;
  requiredConfirmations?: number;
}

export function createViemMonadTransactionAdapter(config: ViemMonadTransactionAdapterConfig) {
  if (!/^https?:\/\//.test(config.rpcUrl)) throw new Error("rpcUrl must use HTTP or HTTPS");
  if (!/^0x[0-9a-fA-F]{64}$/.test(config.privateKey)) throw new Error("privateKey must contain exactly 32 bytes");
  if (![config.registry, config.validation, config.rewards]
    .every((address) => isAddress(address) && address.toLowerCase() !== zeroAddress)) {
    throw new Error("Dadieng contract addresses must be valid nonzero EVM addresses");
  }
  const chainId = config.chainId ?? 10_143;
  if (!Number.isSafeInteger(chainId) || chainId < 1) throw new Error("chainId must be a positive safe integer");
  const chain = defineChain({
    id: chainId,
    name: chainId === 10_143 ? "Monad Testnet" : `Dadieng chain ${chainId}`,
    nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [config.rpcUrl] } },
  });
  const account = privateKeyToAccount(config.privateKey);
  const transport = http(config.rpcUrl, { retryCount: 0, timeout: 10_000 });
  const publicClient = createPublicClient({ chain, transport });
  const walletClient = createWalletClient({ account, chain, transport });
  return new ViemMonadTransactionAdapter(
    publicClient,
    walletClient,
    account,
    { registry: config.registry, validation: config.validation, rewards: config.rewards },
    config.requiredConfirmations,
  );
}
