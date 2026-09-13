import { randomUUID } from "node:crypto";
import {
  DADIENG_DECISION_SCHEMA_VERSION,
  dadiengEventSchema,
  policyDecisionSchema,
  type DadiengEvent,
  type DefenseRule,
  type PolicyDecision,
} from "@dadieng/schemas";

export interface PolicyEngineRuntime {
  createId(): string;
  now(): string;
}

const defaultRuntime: PolicyEngineRuntime = {
  createId: randomUUID,
  now: () => new Date().toISOString(),
};

export class LocalPolicyEngine {
  constructor(
    private readonly defenses: DefenseRule[],
    private readonly runtime: PolicyEngineRuntime = defaultRuntime,
  ) {}

  evaluate(event: DadiengEvent): PolicyDecision {
    dadiengEventSchema.parse(event);

    for (const defense of this.defenses) {
      const result = defense.evaluate(event);
      if (result) {
        return policyDecisionSchema.parse({
          ...result,
          schemaVersion: DADIENG_DECISION_SCHEMA_VERSION,
          decisionId: this.runtime.createId(),
          eventId: event.eventId,
          evaluatedAt: this.runtime.now(),
        });
      }
    }

    return policyDecisionSchema.parse({
      schemaVersion: DADIENG_DECISION_SCHEMA_VERSION,
      decisionId: this.runtime.createId(),
      eventId: event.eventId,
      outcome: "ALLOW",
      reasonCodes: ["NO_DEFENSE_MATCH"],
      matchedDefenseIds: [],
      evaluatedAt: this.runtime.now(),
    });
  }
}
