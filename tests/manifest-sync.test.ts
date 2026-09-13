import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  contentHash,
  createDefenseBundle,
  type DefenseBundle,
} from "@dadieng/defense-module";
import { createMcpBoundaryBundle } from "@dadieng/defense-module/mcp-boundary";
import { defenseVersionKey, sha256Commitment } from "@dadieng/contracts-client";
import {
  DADIENG_MANIFEST_SCHEMA_VERSION,
  stableManifestSchema,
  stableManifestSigningMessage,
  type StableManifest,
} from "@dadieng/schemas";
import {
  ControlPlaneHttpApp,
  ControlPlaneService,
  FixedWindowRateLimiter,
  InMemoryControlPlaneRepository,
  StableManifestPublisher,
  StaticApiKeyAuthenticator,
  type HttpRuntime,
  type StableVersionReader,
} from "@dadieng/control-plane";
import {
  FileSystemManifestCache,
  InMemoryManifestCache,
  ManifestSynchronizer,
  type ManifestChainReader,
  type ManifestFetcher,
} from "@dadieng/sdk";
import { getAddress, recoverMessageAddress, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const PRIVATE_KEY = `0x${"11".repeat(32)}` as Hex;
const OTHER_PRIVATE_KEY = `0x${"22".repeat(32)}` as Hex;
const ACCOUNT = privateKeyToAccount(PRIVATE_KEY);
const REGISTRY = getAddress("0x1111111111111111111111111111111111111111");
const CHAIN_ID = 10_143;
const NOW = "2026-09-04T12:00:00.000Z";
const ARTIFACT_URI = "https://api.dadieng.test/v1/defense-versions/dadieng.mcp-boundary%400.2.0/bundle";

function versionState(bundle: DefenseBundle, status = 3) {
  return {
    status,
    manifestHash: sha256Commitment(contentHash(bundle.manifest)),
    artifactHash: sha256Commitment(bundle.manifest.artifactHash),
  };
}

function readerFor(bundle: DefenseBundle, status = 3): ManifestChainReader & StableVersionReader {
  return {
    async getCode() { return "0x6000"; },
    async getVersion() { return versionState(bundle, status); },
  };
}

class MapFetcher implements ManifestFetcher {
  constructor(readonly resources: Map<string, unknown>) {}
  async get(uri: string) {
    if (!this.resources.has(uri)) throw new Error(`offline: ${uri}`);
    return structuredClone(this.resources.get(uri));
  }
}

async function signedManifest(
  bundle: DefenseBundle,
  options: Partial<Omit<StableManifest, "signature" | "versions">> & { privateKey?: Hex } = {},
) {
  const unsigned: Omit<StableManifest, "signature"> = {
    schemaVersion: DADIENG_MANIFEST_SCHEMA_VERSION,
    channel: options.channel ?? "stable",
    generatedAt: options.generatedAt ?? NOW,
    expiresAt: options.expiresAt ?? "2026-09-04T12:05:00.000Z",
    chainId: options.chainId ?? CHAIN_ID,
    registryAddress: options.registryAddress ?? REGISTRY,
    versions: [{
      defenseId: bundle.manifest.defenseId,
      version: bundle.manifest.version,
      artifactHash: bundle.manifest.artifactHash,
      artifactUri: ARTIFACT_URI,
      status: "stable",
    }],
    previousManifestHash: options.previousManifestHash ?? null,
  };
  const account = privateKeyToAccount(options.privateKey ?? PRIVATE_KEY);
  return stableManifestSchema.parse({
    ...unsigned,
    signature: await account.signMessage({ message: stableManifestSigningMessage(unsigned) }),
  });
}

function synchronizer(
  manifest: StableManifest,
  bundle: DefenseBundle,
  options: {
    reader?: ManifestChainReader;
    fetcher?: ManifestFetcher;
    cache?: InMemoryManifestCache | FileSystemManifestCache;
    signerAddress?: Address;
    failMode?: "open" | "closed" | "last-known-good";
    adapters?: string[];
  } = {},
) {
  const manifestUrl = "https://api.dadieng.test/v1/channels/stable/manifest";
  return new ManifestSynchronizer({
    manifestUrl,
    signerAddress: options.signerAddress ?? ACCOUNT.address,
    chainId: CHAIN_ID,
    registryAddress: REGISTRY,
    sdkVersion: "0.1.0",
    adapters: options.adapters ?? ["mcp"],
    failMode: options.failMode ?? "closed",
    maxClockSkewMs: 0,
  }, options.reader ?? readerFor(bundle), options.fetcher ?? new MapFetcher(new Map([
    [manifestUrl, manifest],
    [ARTIFACT_URI, bundle],
  ])), options.cache ?? new InMemoryManifestCache(), () => NOW);
}

function incompatibleBundle(): DefenseBundle {
  const bundle = createMcpBoundaryBundle();
  const { artifactHash: _artifactHash, suiteHash: _suiteHash, sbomHash: _sbomHash, ...manifest } = bundle.manifest;
  return createDefenseBundle({
    ...manifest,
    compatibility: { ...manifest.compatibility, adapters: ["openai-agents"] },
  }, bundle.artifact, bundle.suite, bundle.sbom);
}

const temporaryRoots: string[] = [];
afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("Phase 12 stable manifest publication", () => {
  it("publishes, signs, persists, and serves a cacheable stable manifest and immutable artifact", async () => {
    const bundle = createMcpBoundaryBundle();
    const repository = new InMemoryControlPlaneRepository();
    await repository.saveDefenseVersion({
      defenseVersionId: `${bundle.manifest.defenseId}@${bundle.manifest.version}`,
      defenseId: bundle.manifest.defenseId,
      bundle,
      status: "candidate",
      createdAt: NOW,
    });
    const publisher = new StableManifestPublisher(repository, readerFor(bundle), {
      chainId: CHAIN_ID,
      registryAddress: REGISTRY,
      publicBaseUrl: "https://api.dadieng.test",
      privateKey: PRIVATE_KEY,
      ttlSeconds: 300,
    }, { now: () => NOW });
    const service = new ControlPlaneService(repository, undefined, undefined, undefined, undefined, undefined, undefined, undefined, publisher);
    const httpRuntime: HttpRuntime = { createRequestId: () => "request_manifest", now: () => NOW };
    const app = new ControlPlaneHttpApp(service, new StaticApiKeyAuthenticator([]), new FixedWindowRateLimiter(), httpRuntime);

    const manifestResponse = await app.handle(new Request("https://api.dadieng.test/v1/channels/stable/manifest"));
    const manifestBody = await manifestResponse.json() as Record<string, unknown>;
    const manifest = stableManifestSchema.parse(manifestBody);
    const { signature, ...unsigned } = manifest;
    expect(await recoverMessageAddress({ message: stableManifestSigningMessage(unsigned), signature: signature as Hex }))
      .toBe(ACCOUNT.address);
    expect(manifest.versions).toHaveLength(1);
    expect(manifest.expiresAt).toBe("2026-09-04T12:05:00.000Z");
    expect(manifestResponse.headers.get("cache-control")).toBe("public, max-age=60");
    expect(manifestResponse.headers.get("etag")).toBe(`"${contentHash(manifest)}"`);
    expect(manifestResponse.headers.get("x-request-id")).toBe("request_manifest");
    expect(manifestBody.requestId).toBeUndefined();

    const notModified = await app.handle(new Request("https://api.dadieng.test/v1/channels/stable/manifest", {
      headers: { "if-none-match": manifestResponse.headers.get("etag")! },
    }));
    expect(notModified.status).toBe(304);

    const artifact = await app.handle(new Request(ARTIFACT_URI));
    expect(artifact.status).toBe(200);
    expect(artifact.headers.get("cache-control")).toContain("immutable");
    expect((await artifact.json() as DefenseBundle).manifest.artifactHash).toBe(bundle.manifest.artifactHash);
  });
});

describe("Phase 12 SDK synchronization", () => {
  it("verifies signature, compatibility, Monad commitments, and the shadow suite before activation", async () => {
    const bundle = createMcpBoundaryBundle();
    const manifest = await signedManifest(bundle);
    let active = [] as string[];
    const sync = synchronizer(manifest, bundle);

    const result = await sync.sync((defenses) => { active = defenses.map((defense) => `${defense.defenseId}@${defense.version}`); });

    expect(result.status).toBe("activated");
    expect(active).toEqual(["dadieng.mcp-boundary@0.2.0"]);
  });

  it("revalidates an unchanged manifest against Monad before reactivation", async () => {
    const bundle = createMcpBoundaryBundle();
    const manifest = await signedManifest(bundle);
    let status = 3;
    const reader: ManifestChainReader = {
      async getCode() { return "0x6000"; },
      async getVersion() { return versionState(bundle, status); },
    };
    const sync = synchronizer(manifest, bundle, { reader });
    await sync.sync(() => undefined);
    status = 4;

    await expect(sync.sync(() => undefined)).rejects.toThrow("Stable manifest synchronization failed");
  });

  it.each([
    ["wrong signer", async (bundle: DefenseBundle) => ({ manifest: await signedManifest(bundle, { privateKey: OTHER_PRIVATE_KEY }), bundle, status: 3, adapters: ["mcp"] })],
    ["expired manifest", async (bundle: DefenseBundle) => ({
      manifest: await signedManifest(bundle, {
        generatedAt: "2026-09-04T11:00:00.000Z",
        expiresAt: "2026-09-04T11:30:00.000Z",
      }),
      bundle,
      status: 3,
      adapters: ["mcp"],
    })],
    ["non-stable Monad version", async (bundle: DefenseBundle) => ({ manifest: await signedManifest(bundle), bundle, status: 2, adapters: ["mcp"] })],
    ["incompatible adapter", async () => {
      const bundle = incompatibleBundle();
      return { manifest: await signedManifest(bundle), bundle, status: 3, adapters: ["mcp"] };
    }],
  ])("fails closed for %s", async (_name, arrange) => {
    const fixture = await arrange(createMcpBoundaryBundle());
    await expect(synchronizer(fixture.manifest, fixture.bundle, {
      reader: readerFor(fixture.bundle, fixture.status),
      adapters: fixture.adapters,
    }).sync(() => undefined)).rejects.toThrow("Stable manifest synchronization failed");
  });

  it("rejects an artifact changed after publication", async () => {
    const bundle = createMcpBoundaryBundle();
    const manifest = await signedManifest(bundle);
    const tampered = structuredClone(bundle);
    tampered.artifact.rules[0]!.description = "changed after signing";
    await expect(synchronizer(manifest, tampered, { reader: readerFor(bundle) }).sync(() => undefined))
      .rejects.toThrow("Stable manifest synchronization failed");
  });

  it("retains current and previous sets and rejects a discontinuous update", async () => {
    const bundle = createMcpBoundaryBundle();
    const first = await signedManifest(bundle);
    const cache = new InMemoryManifestCache();
    await synchronizer(first, bundle, { cache }).sync(() => undefined);
    const firstHash = contentHash(first);
    const second = await signedManifest(bundle, {
      generatedAt: "2026-09-04T12:01:00.000Z",
      expiresAt: "2026-09-04T12:06:00.000Z",
      previousManifestHash: firstHash,
    });
    await new ManifestSynchronizer({
      manifestUrl: "https://api.dadieng.test/v1/channels/stable/manifest",
      signerAddress: ACCOUNT.address,
      chainId: CHAIN_ID,
      registryAddress: REGISTRY,
      sdkVersion: "0.1.0",
      adapters: ["mcp"],
      failMode: "closed",
      maxClockSkewMs: 0,
    }, readerFor(bundle), new MapFetcher(new Map([
      ["https://api.dadieng.test/v1/channels/stable/manifest", second],
      [ARTIFACT_URI, bundle],
    ])), cache, () => "2026-09-04T12:01:00.000Z").sync(() => undefined);
    expect((await cache.load()).previous?.manifestHash).toBe(firstHash);

    const fork = await signedManifest(bundle, {
      generatedAt: "2026-09-04T12:02:00.000Z",
      expiresAt: "2026-09-04T12:07:00.000Z",
      previousManifestHash: null,
    });
    await expect(synchronizer(fork, bundle, { cache }).sync(() => undefined))
      .rejects.toThrow("Stable manifest synchronization failed");
  });

  it("restores the last verified set from an owner-only file cache while offline", async () => {
    const root = await mkdtemp(join(tmpdir(), "dadieng-manifest-"));
    temporaryRoots.push(root);
    const cachePath = join(root, "nested", "stable.json");
    const bundle = createMcpBoundaryBundle();
    const manifest = await signedManifest(bundle);
    await synchronizer(manifest, bundle, { cache: new FileSystemManifestCache(cachePath) }).sync(() => undefined);
    const offline: ManifestFetcher = { async get() { throw new Error("network unavailable"); } };
    let restored = 0;
    const result = await synchronizer(manifest, bundle, {
      cache: new FileSystemManifestCache(cachePath),
      fetcher: offline,
      failMode: "last-known-good",
    }).sync((defenses) => { restored = defenses.length; });

    expect(result.status).toBe("using-last-known-good");
    expect(restored).toBe(1);
    expect((await stat(cachePath)).mode & 0o777).toBe(0o600);
  });

  it("rejects an offline cache whose manifest was replaced by another signer", async () => {
    const bundle = createMcpBoundaryBundle();
    const forged = await signedManifest(bundle, { privateKey: OTHER_PRIVATE_KEY });
    const cache = new InMemoryManifestCache();
    await cache.save({
      current: {
        manifestHash: contentHash(forged),
        manifest: forged,
        bundles: [bundle],
        activatedAt: NOW,
      },
    });
    const offline: ManifestFetcher = { async get() { throw new Error("network unavailable"); } };

    await expect(synchronizer(forged, bundle, {
      cache,
      fetcher: offline,
      failMode: "last-known-good",
    }).sync(() => undefined)).rejects.toThrow("Stable manifest synchronization failed");
  });

  it("supports explicit fail-open and fail-closed behavior when no verified cache exists", async () => {
    const bundle = createMcpBoundaryBundle();
    const manifest = await signedManifest(bundle);
    const offline: ManifestFetcher = { async get() { throw new Error("network unavailable"); } };
    const open = await synchronizer(manifest, bundle, { fetcher: offline, failMode: "open" }).sync(() => undefined);
    expect(open.status).toBe("failed-open");
    await expect(synchronizer(manifest, bundle, { fetcher: offline, failMode: "closed" }).sync(() => undefined))
      .rejects.toThrow("Stable manifest synchronization failed");
  });
});
