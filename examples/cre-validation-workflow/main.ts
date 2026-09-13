import {
  Runner,
  consensusIdenticalAggregation,
  cre,
  ok,
  text,
  type HTTPSendRequester,
  type Runtime,
  type SecretsProvider,
} from "@chainlink/cre-sdk";
import { z } from "zod";

const configSchema = z.object({
  schedule: z.string().min(1),
  controlPlaneUrl: z.string().url().refine((url) => url.startsWith("https://"), "CRE callbacks require HTTPS"),
  network: z.literal("monad-testnet"),
});

type Config = z.infer<typeof configSchema>;

type CycleReceipt = {
  cycleId: string;
  status: "idle" | "replaying" | "awaiting-attestations" | "submitted";
  reportHashes: string[];
};

const runCycleRequest = (sender: HTTPSendRequester, config: Config, authorization: string) => {
  const response = sender.sendRequest({
    url: config.controlPlaneUrl,
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body: btoa(JSON.stringify({ network: config.network, coordinator: "chainlink-cre" })),
  }).result();
  if (!ok(response)) throw new Error(`Dadieng validation callback failed with status ${response.statusCode}`);
  return text(response);
};

function onSchedule(authorization: string) {
  return (runtime: Runtime<Config>): CycleReceipt => {
    const http = new cre.capabilities.HTTPClient();
    const raw = http.sendRequest(runtime, runCycleRequest, consensusIdenticalAggregation<string>())(
      runtime.config,
      authorization,
    ).result();
    const receipt = JSON.parse(raw) as CycleReceipt;
    if (!receipt.cycleId || !["idle", "replaying", "awaiting-attestations", "submitted"].includes(receipt.status)) {
      throw new Error("Dadieng returned an invalid sanitized cycle receipt");
    }
    if (!Array.isArray(receipt.reportHashes) || receipt.reportHashes.some((hash) => !/^sha256:[a-f0-9]{64}$/.test(hash))) {
      throw new Error("Dadieng returned an invalid report commitment");
    }
    runtime.log(`Dadieng validation cycle ${receipt.cycleId}: ${receipt.status}`);
    return receipt;
  };
}

function initWorkflow(config: Config, secrets: SecretsProvider) {
  const apiToken = secrets.getSecret({ id: "DADIENG_CRE_API_TOKEN", namespace: "dadieng" }).result().value;
  if (!apiToken) throw new Error("DADIENG_CRE_API_TOKEN is unavailable");
  const trigger = new cre.capabilities.CronCapability().trigger({ schedule: config.schedule });
  return [cre.handler(trigger, onSchedule(`Bearer ${apiToken}`))];
}

export async function main() {
  const runner = await Runner.newRunner<Config>({ configSchema });
  await runner.run(initWorkflow);
}

main();
