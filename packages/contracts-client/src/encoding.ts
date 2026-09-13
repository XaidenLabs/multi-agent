import { encodeAbiParameters, encodeFunctionData, keccak256, parseAbi, parseAbiParameters, stringToHex, type Address, type Hex } from "viem";
import type { ChainOperationRequest } from "./operations.js";

export interface DadiengContractAddresses {
  registry: Address;
  validation: Address;
  rewards: Address;
}

const registryAbi = parseAbi([
  "function registerDefense(bytes32 defenseId,uint256 authorAgentId)",
  "function publishVersion(bytes32 defenseId,uint64 major,uint64 minor,uint64 patch,bytes32 manifestHash,bytes32 artifactHash,string manifestURI,bytes32 supersedes) returns (bytes32)",
  "function publishReplayBundle(bytes32 key,bytes32 reportHash,string reportURI,uint32 attackPassed,uint32 attackTotal,uint32 controlPassed,uint32 controlTotal)",
  "function publishReceipt(bytes32 receiptId,bytes32 receiptHash,bytes32 evidenceHash,bytes32 attackClass,uint256 reporterAgentId)",
  "function promoteVersion(bytes32 key)",
  "function quarantineVersion(bytes32 key,bytes32 reasonCode,bytes32 evidenceHash,bytes32 replacementVersionKey)",
  "function revokeVersion(bytes32 key,bytes32 reasonCode,bytes32 evidenceHash,bytes32 replacementVersionKey)",
]);

const validationAbi = parseAbi([
  "function submitAttestation(bytes32 versionKey,(bool passed,bytes32 reportHash,string reportURI,uint32 attackPassed,uint32 attackTotal,uint32 controlPassed,uint32 controlTotal) input)",
]);

const rewardsAbi = parseAbi([
  "function commitUsageBatch(uint256 epoch,uint256 adopterId,bytes32 versionKey,bytes32 root,uint64 count) returns (bytes32)",
]);

export function bytes32Identifier(value: string): Hex {
  if (!value) throw new Error("Identifier cannot be empty");
  return keccak256(stringToHex(value));
}

export function decimalUint(value: string, field: string): bigint {
  if (!/^(0|[1-9]\d*)$/.test(value)) throw new Error(`${field} must be an unsigned decimal integer`);
  return BigInt(value);
}

function positiveDecimalUint(value: string, field: string): bigint {
  const parsed = decimalUint(value, field);
  if (parsed === 0n) throw new Error(`${field} must be positive`);
  return parsed;
}

function semanticVersionParts(version: string): readonly [bigint, bigint, bigint] {
  const parts = version.split(".").map((part) => decimalUint(part, "version"));
  if (parts.length !== 3 || parts.some((part) => part > 18_446_744_073_709_551_615n)) {
    throw new Error("version must contain three uint64 components");
  }
  return [parts[0]!, parts[1]!, parts[2]!];
}

export function defenseVersionKey(defenseId: string, version: string): Hex {
  const [major, minor, patch] = semanticVersionParts(version);
  return keccak256(encodeAbiParameters(
    parseAbiParameters("bytes32 defenseId, uint64 major, uint64 minor, uint64 patch"),
    [bytes32Identifier(defenseId), major, minor, patch],
  ));
}

export function sha256Commitment(value: string): Hex {
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) throw new Error("Expected a lowercase SHA-256 commitment");
  return `0x${value.slice(7)}`;
}

export function encodeDadiengOperation(
  operation: ChainOperationRequest,
  addresses: DadiengContractAddresses,
): { to: Address; data: Hex } {
  switch (operation.kind) {
    case "register-defense":
      return {
        to: addresses.registry,
        data: encodeFunctionData({
          abi: registryAbi,
          functionName: "registerDefense",
          args: [bytes32Identifier(operation.defenseId), positiveDecimalUint(operation.authorAgentId, "authorAgentId")],
        }),
      };
    case "publish-version": {
      const parts = semanticVersionParts(operation.version);
      return {
        to: addresses.registry,
        data: encodeFunctionData({
          abi: registryAbi,
          functionName: "publishVersion",
          args: [
            bytes32Identifier(operation.defenseId), parts[0]!, parts[1]!, parts[2]!, operation.manifestHash,
            operation.artifactHash, operation.manifestURI, operation.supersedes,
          ],
        }),
      };
    }
    case "publish-replay":
      return {
        to: addresses.registry,
        data: encodeFunctionData({
          abi: registryAbi,
          functionName: "publishReplayBundle",
          args: [
            operation.versionKey, operation.reportHash, operation.reportURI, operation.attackPassed,
            operation.attackTotal, operation.controlPassed, operation.controlTotal,
          ],
        }),
      };
    case "publish-receipt":
      return {
        to: addresses.registry,
        data: encodeFunctionData({
          abi: registryAbi,
          functionName: "publishReceipt",
          args: [
            bytes32Identifier(operation.receiptId), operation.receiptHash, operation.evidenceHash,
            bytes32Identifier(operation.attackClass), positiveDecimalUint(operation.reporterAgentId, "reporterAgentId"),
          ],
        }),
      };
    case "submit-attestation":
      return {
        to: addresses.validation,
        data: encodeFunctionData({
          abi: validationAbi,
          functionName: "submitAttestation",
          args: [operation.versionKey, {
            passed: operation.passed,
            reportHash: operation.reportHash,
            reportURI: operation.reportURI,
            attackPassed: operation.attackPassed,
            attackTotal: operation.attackTotal,
            controlPassed: operation.controlPassed,
            controlTotal: operation.controlTotal,
          }],
        }),
      };
    case "promote-version":
      return { to: addresses.registry, data: encodeFunctionData({ abi: registryAbi, functionName: "promoteVersion", args: [operation.versionKey] }) };
    case "quarantine-version":
    case "revoke-version":
      return {
        to: addresses.registry,
        data: encodeFunctionData({
          abi: registryAbi,
          functionName: operation.kind === "quarantine-version" ? "quarantineVersion" : "revokeVersion",
          args: [operation.versionKey, bytes32Identifier(operation.reasonCode), operation.evidenceHash, operation.replacementVersionKey],
        }),
      };
    case "commit-usage-batch":
      return {
        to: addresses.rewards,
        data: encodeFunctionData({
          abi: rewardsAbi,
          functionName: "commitUsageBatch",
          args: [
            decimalUint(operation.epoch, "epoch"), positiveDecimalUint(operation.adopterAgentId, "adopterAgentId"),
            operation.versionKey, operation.root, decimalUint(operation.count, "count"),
          ],
        }),
      };
  }
}
