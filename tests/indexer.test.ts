import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { emptyMetrics, eventId, freshness, transitionVersionMetrics } from "../indexer/src/model.js";

describe("Phase 14 Envio indexer", () => {
  it("tracks Stable and Quarantined counts across reversible event projections", () => {
    const initial = emptyMetrics();
    const stable = transitionVersionMetrics(initial, 2, 3);
    const quarantined = transitionVersionMetrics(stable, 3, 4);
    const restored = transitionVersionMetrics(quarantined, 4, 3);

    expect(stable).toMatchObject({ stableVersionCount: 1, quarantinedVersionCount: 0 });
    expect(quarantined).toMatchObject({ stableVersionCount: 0, quarantinedVersionCount: 1 });
    expect(restored).toMatchObject({ stableVersionCount: 1, quarantinedVersionCount: 0 });
  });

  it("marks missing or old projections stale and creates reorg-stable event IDs", () => {
    expect(freshness(0n, 100n)).toEqual({ ageSeconds: 100n, stale: true });
    expect(freshness(90n, 100n)).toEqual({ ageSeconds: 10n, stale: false });
    expect(freshness(80n, 100n)).toEqual({ ageSeconds: 20n, stale: true });
    expect(eventId("0xABC", 7)).toBe("0xabc:7");
  });

  it("commits the three-contract HyperIndex configuration, derived schema, and lifecycle handlers", async () => {
    const [config, schema, handlers] = await Promise.all([
      readFile(new URL("../indexer/config.yaml", import.meta.url), "utf8"),
      readFile(new URL("../indexer/schema.graphql", import.meta.url), "utf8"),
      readFile(new URL("../indexer/src/handlers/Dadieng.ts", import.meta.url), "utf8"),
    ]);

    for (const contract of ["DadiengRegistry", "DadiengValidation", "DadiengRewards"]) {
      expect(config).toContain(`name: ${contract}`);
    }
    for (const entity of ["DefenseVersion", "SafetyAction", "Validator", "ThreatReceipt", "UsageBatch", "RewardClaim"]) {
      expect(schema).toContain(`type ${entity}`);
    }
    for (const event of ["VersionSafetyAction", "AttestationSubmitted", "UsageBatchRecorded", "RewardClaimed"]) {
      expect(handlers).toContain(`event: "${event}"`);
    }
    expect(config).toContain("rollback_on_reorg: true");
  });
});
