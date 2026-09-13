import { describe, expect, it } from "vitest";
import { contentHash, createDefenseBundle, type DefenseBundle } from "@dadieng/defense-module";
import { createMcpBoundaryBundle } from "@dadieng/defense-module/mcp-boundary";
import {
  ChainOperationCoordinator,
  defenseVersionKey,
  sha256Commitment,
  type MonadTransactionAdapter,
} from "@dadieng/contracts-client";
import {
  ControlPlaneHttpApp,
  ControlPlaneService,
  FixedWindowRateLimiter,
  InMemoryControlPlaneRepository,
  StableManifestPublisher,
  StaticApiKeyAuthenticator,
  type StableVersionReader,
} from "@dadieng/control-plane";
import {
  InMemoryManifestCache,
  ManifestSynchronizer,
  type ManifestChainReader,
  type ManifestFetcher,
} from "@dadieng/sdk";
import { getAddress, zeroHash, type Hex } from "viem";

const REGISTRY = getAddress("0x1111111111111111111111111111111111111111");
const PRIVATE_KEY = `0x${"33".repeat(32)}` as Hex;
const CHAIN_ID = 10_143;
const API_KEY = "dadieng-safety-key-0001";

function withVersion(source: DefenseBundle, version: string): DefenseBundle {
  const { artifactHash: _artifact, suiteHash: _suite, sbomHash: _sbom, ...manifest } = source.manifest;
  return createDefenseBundle({ ...manifest, version }, source.artifact, source.suite, source.sbom);
}

function state(bundle: DefenseBundle, status: number) {
  return {
    status,
    manifestHash: sha256Commitment(contentHash(bundle.manifest)),
    artifactHash: sha256Commitment(bundle.manifest.artifactHash),
  };
}

describe("Phase 13 quarantine and rollback", () => {
  it("queues a guardian quarantine with public evidence and a same-defense replacement", async () => {
    const oldBundle = createMcpBoundaryBundle();
    const newBundle = withVersion(oldBundle, "0.3.0");
    const repository = new InMemoryControlPlaneRepository();
    for (const bundle of [oldBundle, newBundle]) {
      await repository.saveDefenseVersion({
        defenseVersionId: `${bundle.manifest.defenseId}@${bundle.manifest.version}`,
        defenseId: bundle.manifest.defenseId,
        bundle,
        status: "candidate",
        createdAt: "2026-09-04T12:00:00.000Z",
      });
    }
    const adapter: MonadTransactionAdapter = {
      async prepare() { return { transactionHash: `0x${"44".repeat(32)}`, serializedTransaction: "0x01" }; },
      async broadcast() { return undefined; },
      async inspect() { return { status: "pending" }; },
    };
    let id = 0;
    const coordinator = new ChainOperationCoordinator(repository, adapter, {
      createId: () => `safety_operation_${++id}`,
      now: () => "2026-09-04T12:00:00.000Z",
    });
    const service = new ControlPlaneService(repository, undefined, undefined, undefined, coordinator);
    const app = new ControlPlaneHttpApp(service, new StaticApiKeyAuthenticator([{
      token: API_KEY,
      principal: { subject: "guardian", tenantId: "dadieng", scopes: ["safety:write"] },
    }]), new FixedWindowRateLimiter(), {
      createRequestId: () => "request_safety",
      now: () => "2026-09-04T12:00:00.000Z",
    });
    const evidenceHash = contentHash({ incident: "sanitized utility regression" });
    const response = await app.handle(new Request(
      "https://api.dadieng.test/v1/defense-versions/dadieng.mcp-boundary%400.3.0/quarantine",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${API_KEY}`,
          "content-type": "application/json",
          "idempotency-key": "quarantine-mcp-030",
        },
        body: JSON.stringify({
          reasonCode: "UTILITY_REGRESSION",
          evidenceHash,
          replacementDefenseVersionId: "dadieng.mcp-boundary@0.2.0",
        }),
      },
    ));
    const body = await response.json() as Record<string, any>;

    expect(response.status).toBe(202);
    expect(body).toMatchObject({
      defenseVersionId: "dadieng.mcp-boundary@0.3.0",
      status: "pending",
      reasonCode: "UTILITY_REGRESSION",
      replacementDefenseVersionId: "dadieng.mcp-boundary@0.2.0",
    });
    expect((await repository.getChainOperation("safety_operation_1"))?.request).toEqual({
      kind: "quarantine-version",
      versionKey: defenseVersionKey("dadieng.mcp-boundary", "0.3.0"),
      reasonCode: "UTILITY_REGRESSION",
      evidenceHash: sha256Commitment(evidenceHash),
      replacementVersionKey: defenseVersionKey("dadieng.mcp-boundary", "0.2.0"),
    });
  });

  it("publishes a linked rollback manifest and activates the highest older Stable version", async () => {
    const oldBundle = createMcpBoundaryBundle();
    const newBundle = withVersion(oldBundle, "0.3.0");
    const repository = new InMemoryControlPlaneRepository();
    for (const bundle of [oldBundle, newBundle]) {
      await repository.saveDefenseVersion({
        defenseVersionId: `${bundle.manifest.defenseId}@${bundle.manifest.version}`,
        defenseId: bundle.manifest.defenseId,
        bundle,
        status: "candidate",
        createdAt: "2026-09-04T12:00:00.000Z",
      });
    }
    const statuses = new Map<string, number>([
      [defenseVersionKey(oldBundle.manifest.defenseId, oldBundle.manifest.version), 3],
      [defenseVersionKey(newBundle.manifest.defenseId, newBundle.manifest.version), 3],
    ]);
    const bundles = new Map<string, DefenseBundle>([
      [defenseVersionKey(oldBundle.manifest.defenseId, oldBundle.manifest.version), oldBundle],
      [defenseVersionKey(newBundle.manifest.defenseId, newBundle.manifest.version), newBundle],
    ]);
    const reader: StableVersionReader & ManifestChainReader = {
      async getCode() { return "0x6000"; },
      async getVersion(_registry, key) {
        const bundle = bundles.get(key);
        if (!bundle) return { status: 0, manifestHash: zeroHash, artifactHash: zeroHash };
        return state(bundle, statuses.get(key) ?? 0);
      },
    };
    let now = "2026-09-04T12:00:00.000Z";
    const publisher = new StableManifestPublisher(repository, reader, {
      chainId: CHAIN_ID,
      registryAddress: REGISTRY,
      publicBaseUrl: "https://api.dadieng.test",
      privateKey: PRIVATE_KEY,
      ttlSeconds: 300,
    }, { now: () => now });
    const first = await publisher.get("stable");
    expect(first.manifest.versions.map((version) => version.version)).toEqual(["0.3.0"]);

    const cache = new InMemoryManifestCache();
    const manifestUrl = "https://api.dadieng.test/v1/channels/stable/manifest";
    const resources = new Map<string, unknown>([
      [manifestUrl, first.manifest],
      [first.manifest.versions[0]!.artifactUri, newBundle],
    ]);
    const fetcher: ManifestFetcher = {
      async get(uri) {
        if (!resources.has(uri)) throw new Error("missing fixture");
        return structuredClone(resources.get(uri));
      },
    };
    const createSync = () => new ManifestSynchronizer({
      manifestUrl,
      signerAddress: publisher.signerAddress,
      chainId: CHAIN_ID,
      registryAddress: REGISTRY,
      sdkVersion: "0.1.0",
      adapters: ["mcp"],
      failMode: "closed",
      maxClockSkewMs: 0,
    }, reader, fetcher, cache, () => now);
    let activeVersion = "";
    await createSync().sync((defenses) => { activeVersion = defenses[0]?.version ?? ""; });
    expect(activeVersion).toBe("0.3.0");

    statuses.set(defenseVersionKey(newBundle.manifest.defenseId, newBundle.manifest.version), 4);
    now = "2026-09-04T12:01:00.000Z";
    const rollback = await publisher.get("stable");
    expect(rollback.manifest.previousManifestHash).toBe(first.manifestHash);
    expect(rollback.manifest.versions.map((version) => version.version)).toEqual(["0.2.0"]);
    resources.set(manifestUrl, rollback.manifest);
    resources.set(rollback.manifest.versions[0]!.artifactUri, oldBundle);

    await createSync().sync((defenses) => { activeVersion = defenses[0]?.version ?? ""; });
    expect(activeVersion).toBe("0.2.0");
    expect((await cache.load()).previous?.manifestHash).toBe(first.manifestHash);
  });
});
