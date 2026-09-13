import { createHash } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import {
  QwenRedTeamClient,
  decryptEvidenceWithMera,
  encryptEvidenceWithMera,
  runCreValidationWorkflow,
  signParticipantAction,
  type PrfOutputProvider,
  type ReplayProposal,
} from "@dadieng/sponsor-integrations";

const proposal: ReplayProposal = { id: "variant-1", attackClass: "tool_poisoning", fixtureHash: `sha256:${"1".repeat(64)}` };
const replay = async (input: ReplayProposal) => ({ proposalId: input.id, reportHash: `sha256:${"2".repeat(64)}` as const, releaseEligible: true, worker: "worker-a", signature: "0x01" as const });

describe("sponsor integrations", () => {
  it("lets CRE finalize only after deterministic replay and independent quorum", async () => {
    const finalized: unknown[] = [];
    const result = await runCreValidationWorkflow(
      { defenseVersionId: "version-1", proposals: [proposal], validatorThreshold: 2 },
      {
        replay,
        attest: async (report) => [
          { validatorId: "validator-b", reportHash: report.reportHash, approved: true, signature: "0x02" },
          { validatorId: "validator-a", reportHash: report.reportHash, approved: true, signature: "0x03" },
        ],
        finalize: async (input) => { finalized.push(input); return "operation-1"; },
      },
    );
    expect(result).toMatchObject({ status: "finalized", operationId: "operation-1", validatorIds: ["validator-a", "validator-b"] });
    expect(finalized).toHaveLength(1);
  });

  it("keeps CRE from finalizing when independent quorum is missing", async () => {
    const result = await runCreValidationWorkflow(
      { defenseVersionId: "version-1", proposals: [proposal], validatorThreshold: 2 },
      { replay, attest: async (report) => [{ validatorId: "validator-a", reportHash: report.reportHash, approved: true, signature: "0x02" }], finalize: async () => { throw new Error("must not finalize"); } },
    );
    expect(result).toMatchObject({ status: "rejected", reason: "Independent validator threshold not met" });
  });

  it("re-derives the same Mera evidence key without persisting it", async () => {
    const provider = (): PrfOutputProvider => ({
      evaluate: async (salt) => new Uint8Array(createHash("sha256").update("passkey-secret").update(salt).digest()),
    });
    const plaintext = new TextEncoder().encode("private synthetic incident evidence");
    const envelope = await encryptEvidenceWithMera(provider(), "dadieng/evidence/tenant-7/receipt-9", plaintext, new Uint8Array(12).fill(7));
    const decrypted = await decryptEvidenceWithMera(provider(), envelope);
    expect(new TextDecoder().decode(decrypted)).toBe("private synthetic incident evidence");
    expect(JSON.stringify(envelope)).not.toContain("private synthetic");
  });

  it("uses a Dynamic wallet to bind protocol intent to the authenticated participant", async () => {
    const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
    const signed = await signParticipantAction(
      { address: account.address, signMessage: (message) => account.signMessage({ message }) },
      { action: "publish-defense", resourceId: "version-1", payloadHash: `0x${"ab".repeat(32)}`, chainId: 10143, issuedAt: "2026-09-04T12:00:00.000Z", expiresAt: "2026-09-04T12:05:00.000Z", nonce: "nonce-1" },
    );
    expect(signed.address).toBe(account.address);
    expect(signed.signature).toMatch(/^0x/);
  });

  it("sends Qwen only the sanitized planning envelope and validates structured variants", async () => {
    let requestBody = "";
    const client = new QwenRedTeamClient({
      apiKey: "test-key",
      fetch: async (_url, init) => {
        requestBody = String(init?.body);
        return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ variants: [{ id: "variant-one", attackClass: "tool_poisoning", objective: "Test instruction/data separation", fixture: { tool: "calendar.search", resultShape: "synthetic" }, expectedSafeOutcome: "BLOCK" }] }) } }] }), { status: 200 });
      },
    });
    const variants = await client.propose({ receiptId: "receipt-1", attackClass: "tool_poisoning", capabilityClasses: ["data.read"], sanitizedSummary: "Untrusted output requested a policy override." });
    expect(variants).toHaveLength(1);
    expect(requestBody).toContain("deterministic assertions");
    expect(requestBody).not.toContain("private_key");
  });

  it("bounds Qwen tool use to sanitized taxonomy inspection", async () => {
    let calls = 0;
    const client = new QwenRedTeamClient({
      apiKey: "test-key",
      fetch: async (_url, init) => {
        calls += 1;
        if (calls === 1) return new Response(JSON.stringify({ choices: [{ message: { content: "", tool_calls: [{ id: "tool-1", type: "function", function: { name: "inspect_defense_taxonomy", arguments: "{}" } }] } }] }), { status: 200 });
        expect(String(init?.body)).toContain('"role":"tool"');
        return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ variants: [{ id: "bounded-variant", attackClass: "prompt_injection", objective: "Exercise the boundary", fixture: { content: "synthetic" }, expectedSafeOutcome: "BLOCK" }] }) } }] }), { status: 200 });
      },
    });
    await expect(client.propose({ receiptId: "receipt-2", attackClass: "prompt_injection", capabilityClasses: ["content.inspect"], sanitizedSummary: "A policy override was detected." })).resolves.toHaveLength(1);
    expect(calls).toBe(2);
  });
});
