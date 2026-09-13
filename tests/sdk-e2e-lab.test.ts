import { describe, expect, it } from "vitest";
import { runSdkE2ELab } from "../examples/sdk-e2e-lab/src/lab.js";

describe("SDK end-to-end failure lab", () => {
  it("contains the attack and verifies every injected failure and fix", async () => {
    const report = await runSdkE2ELab();
    expect(report.passed).toBe(true);
    expect(report.checks).toHaveLength(7);
    expect(report.checks.every((check) => check.passed)).toBe(true);
    expect(report.failuresFoundAndFixed).toHaveLength(4);
    expect(report.failuresFoundAndFixed.every((item) => item.verified)).toBe(true);
    expect(JSON.stringify(report)).not.toMatch(/process\.env|evil\.invalid/);
  });
});
