import { describe, expect, it } from "vitest";
import { maliciousMcpResult } from "../examples/mcp-security-demo/src/fixture.js";
import {
  runComparison,
  runProtectedAgent,
  runVulnerableAgent,
} from "../examples/mcp-security-demo/src/demo.js";

describe("Dadieng Phase 2 MCP demonstration", () => {
  it("shows the vulnerable agent accepting dangerous capability requests", () => {
    const run = runVulnerableAgent();

    expect(run.status).toBe("unsafe_action_proposed");
    expect(run.decision).toBeNull();
    expect(run.capabilityRequests.map((request) => request.capability)).toEqual([
      "secrets.read",
      "network.send",
    ]);
    expect(run.capabilityRequests.every((request) => request.disposition === "proposed")).toBe(true);
    expect(run.capabilityRequests.every((request) => request.executed === false)).toBe(true);
  });

  it("blocks the same fixture before either capability executes", () => {
    const run = runProtectedAgent();

    expect(run.status).toBe("attack_blocked");
    expect(run.decision?.outcome).toBe("BLOCK");
    expect(run.capabilityRequests.every((request) => request.disposition === "blocked")).toBe(true);
    expect(run.capabilityRequests.every((request) => request.executed === false)).toBe(true);
  });

  it("uses the identical content-addressed fixture in both runs", () => {
    const comparison = runComparison();
    expect(comparison.vulnerable.fixtureId).toBe(comparison.protected.fixtureId);
    expect(comparison.vulnerable.fixtureHash).toBe(comparison.protected.fixtureHash);
  });

  it("keeps hostile content out of the public receipt and trace summaries", () => {
    const run = runProtectedAgent();
    const publicMaterial = JSON.stringify({ receipt: run.receipt, steps: run.steps });

    expect(publicMaterial).not.toContain(maliciousMcpResult);
    expect(publicMaterial).not.toContain("attacker.invalid");
    expect(publicMaterial).not.toContain("process.env");
  });

  it("produces a deterministic structured comparison", () => {
    expect(runComparison()).toEqual(runComparison());
  });
});
