import type { ProtectionResult } from "@dadieng/sdk";

export class DadiengBlockedError extends Error {
  readonly code = "DADIENG_BLOCKED";
  readonly decisionId: string;
  readonly receiptId: string | undefined;
  readonly outcome: string;

  constructor(stage: string, result: ProtectionResult) {
    super(`Dadieng blocked ${stage}`);
    this.name = "DadiengBlockedError";
    this.decisionId = result.decision.decisionId;
    this.receiptId = result.receipt?.receiptId;
    this.outcome = result.decision.outcome;
  }
}

export function requireAllowed(stage: string, result: ProtectionResult): void {
  if (result.decision.outcome !== "ALLOW" && result.decision.outcome !== "OBSERVE") {
    throw new DadiengBlockedError(stage, result);
  }
}
