import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  contentHash,
  loadDefenseBundle,
  runDefenseSuite,
  verifyDefenseBundle,
  type DefenseBundle,
} from "@dadieng/defense-module";
import { defenseVersionKey, sha256Commitment } from "@dadieng/contracts-client";
import {
  DADIENG_EVENT_SCHEMA_VERSION,
  stableManifestSchema,
  stableManifestSigningMessage,
  type DefenseRule,
  type StableManifest,
} from "@dadieng/schemas";
import {
  createPublicClient,
  defineChain,
  getAddress,
  http,
  isAddressEqual,
  parseAbi,
  recoverMessageAddress,
  type Address,
  type Hex,
} from "viem";

export type ManifestFailMode = "open" | "closed" | "last-known-good";

export interface ManifestVersionState {
  status: number;
  manifestHash: Hex;
  artifactHash: Hex;
}

export interface ManifestChainReader {
  getCode(address: Address): Promise<Hex | undefined>;
  getVersion(registry: Address, versionKey: Hex): Promise<ManifestVersionState>;
}

const registryAbi = parseAbi([
  "function getVersion(bytes32 key) view returns ((bytes32 defenseId,uint64 major,uint64 minor,uint64 patch,bytes32 manifestHash,bytes32 artifactHash,string manifestURI,uint256 authorAgentId,uint8 status,uint64 createdAt,bytes32 supersedes,bytes32 replayReportHash,string replayReportURI,uint32 attackPassed,uint32 attackTotal,uint32 controlPassed,uint32 controlTotal))",
]);

export function createManifestChainReader(rpcUrl: string, chainId: number): ManifestChainReader {
  if (!/^https?:\/\//.test(rpcUrl)) throw new Error("Manifest RPC URL must use HTTP or HTTPS");
  const chain = defineChain({
    id: chainId,
    name: chainId === 10_143 ? "Monad Testnet" : `Dadieng chain ${chainId}`,
    nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
  const client = createPublicClient({ chain, transport: http(rpcUrl, { retryCount: 0, timeout: 10_000 }) });
  return {
    getCode: (address) => client.getCode({ address }),
    async getVersion(registry, versionKey) {
      const version = await client.readContract({ address: registry, abi: registryAbi, functionName: "getVersion", args: [versionKey] });
      return { status: version.status, manifestHash: version.manifestHash, artifactHash: version.artifactHash };
    },
  };
}

export interface ManifestFetcher {
  get(uri: string): Promise<unknown>;
}

export class HttpManifestFetcher implements ManifestFetcher {
  constructor(private readonly maxBytes = 2_097_152) {}

  async get(uri: string): Promise<unknown> {
    const url = new URL(uri);
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Manifest resources must use HTTP or HTTPS");
    const response = await fetch(url, { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`Manifest resource returned HTTP ${response.status}`);
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > this.maxBytes) {
      await response.body?.cancel();
      throw new Error("Manifest resource exceeds the size limit");
    }
    if (!response.body) throw new Error("Manifest resource returned an empty body");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > this.maxBytes) {
        await reader.cancel();
        throw new Error("Manifest resource exceeds the size limit");
      }
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  }
}

export interface ActivatedManifestSet {
  manifestHash: string;
  manifest: StableManifest;
  bundles: DefenseBundle[];
  activatedAt: string;
}

export interface ManifestCacheState {
  current?: ActivatedManifestSet;
  previous?: ActivatedManifestSet;
}

export interface ManifestCache {
  load(): Promise<ManifestCacheState>;
  save(state: ManifestCacheState): Promise<void>;
}

export class InMemoryManifestCache implements ManifestCache {
  private state: ManifestCacheState = {};
  async load() { return structuredClone(this.state); }
  async save(state: ManifestCacheState) { this.state = structuredClone(state); }
}

export class FileSystemManifestCache implements ManifestCache {
  constructor(readonly path: string) {}

  async load(): Promise<ManifestCacheState> {
    try {
      const input = JSON.parse(await readFile(this.path, "utf8")) as ManifestCacheState;
      return this.verifyState(input);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw error;
    }
  }

  async save(state: ManifestCacheState): Promise<void> {
    const verified = this.verifyState(state);
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    await chmod(dirname(this.path), 0o700);
    const temporary = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(verified, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    await rename(temporary, this.path);
    await chmod(this.path, 0o600);
  }

  private verifyState(input: ManifestCacheState): ManifestCacheState {
    const verifySet = (set: ActivatedManifestSet | undefined) => {
      if (!set) return undefined;
      const manifest = stableManifestSchema.parse(set.manifest);
      const bundles = set.bundles.map((bundle) => verifyDefenseBundle(bundle));
      if (contentHash(manifest) !== set.manifestHash) throw new Error("Cached manifest hash mismatch");
      if (bundles.length !== manifest.versions.length) throw new Error("Cached manifest bundle count mismatch");
      manifest.versions.forEach((version, index) => {
        const bundle = bundles[index];
        if (!bundle || bundle.manifest.defenseId !== version.defenseId
          || bundle.manifest.version !== version.version
          || bundle.manifest.artifactHash !== version.artifactHash) {
          throw new Error("Cached manifest artifact identity mismatch");
        }
      });
      return { ...set, manifest, bundles };
    };
    const current = verifySet(input.current);
    const previous = verifySet(input.previous);
    if (current?.manifest.previousManifestHash !== (previous?.manifestHash ?? null)) {
      throw new Error("Cached manifest continuity mismatch");
    }
    return { ...(current ? { current } : {}), ...(previous ? { previous } : {}) };
  }
}

export interface ManifestSynchronizerConfig {
  manifestUrl: string;
  signerAddress: Address;
  chainId: number;
  registryAddress: Address;
  sdkVersion: string;
  adapters: string[];
  failMode?: ManifestFailMode;
  maxClockSkewMs?: number;
}

export type ManifestSyncResult =
  | { status: "activated" | "unchanged"; manifestHash: string; activeVersions: string[] }
  | { status: "using-last-known-good"; manifestHash: string; activeVersions: string[]; errorCode: "MANIFEST_REFRESH_FAILED" }
  | { status: "failed-open"; manifestHash: null; activeVersions: []; errorCode: "MANIFEST_REFRESH_FAILED" };

function parseVersion(version: string): readonly [number, number, number] {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) throw new Error(`Unsupported semantic version ${version}`);
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compareVersion(left: readonly number[], right: readonly number[]): number {
  for (let index = 0; index < 3; index += 1) {
    if (left[index]! !== right[index]!) return left[index]! < right[index]! ? -1 : 1;
  }
  return 0;
}

export function satisfiesSdkRange(version: string, range: string): boolean {
  const current = parseVersion(version);
  const clauses = range.trim().split(/\s+/);
  if (clauses.length === 0 || clauses.some((clause) => !/^(>=|<=|>|<|=)?\d+\.\d+\.\d+$/.test(clause))) return false;
  return clauses.every((clause) => {
    const match = clause.match(/^(>=|<=|>|<|=)?(\d+\.\d+\.\d+)$/)!;
    const comparison = compareVersion(current, parseVersion(match[2]!));
    switch (match[1] ?? "=") {
      case ">=": return comparison >= 0;
      case "<=": return comparison <= 0;
      case ">": return comparison > 0;
      case "<": return comparison < 0;
      default: return comparison === 0;
    }
  });
}

export class ManifestSynchronizer {
  private readonly failMode: ManifestFailMode;
  private readonly maxClockSkewMs: number;
  private pending: Promise<void> = Promise.resolve();

  constructor(
    private readonly config: ManifestSynchronizerConfig,
    private readonly reader: ManifestChainReader,
    private readonly fetcher: ManifestFetcher = new HttpManifestFetcher(),
    private readonly cache: ManifestCache = new InMemoryManifestCache(),
    private readonly now: () => string = () => new Date().toISOString(),
  ) {
    this.failMode = config.failMode ?? "last-known-good";
    this.maxClockSkewMs = config.maxClockSkewMs ?? 300_000;
    if (config.adapters.length === 0) throw new Error("Manifest synchronization requires at least one adapter");
  }

  async sync(activate: (defenses: DefenseRule[]) => void): Promise<ManifestSyncResult> {
    const operation = this.pending.then(() => this.performSync(activate));
    this.pending = operation.then(() => undefined, () => undefined);
    return operation;
  }

  private async performSync(activate: (defenses: DefenseRule[]) => void): Promise<ManifestSyncResult> {
    let cached: ManifestCacheState;
    try {
      cached = await this.cache.load();
      const input = await this.fetcher.get(this.config.manifestUrl);
      const manifest = stableManifestSchema.parse(input);
      await this.verifyManifestTrust(manifest);
      const now = Date.parse(this.now());
      if (Date.parse(manifest.generatedAt) > now + this.maxClockSkewMs) throw new Error("Stable manifest was generated in the future");
      if (Date.parse(manifest.expiresAt) <= now) throw new Error("Stable manifest has expired");
      const manifestHash = contentHash(manifest);
      if (cached.current) {
        if (cached.current.manifestHash !== manifestHash) {
          if (manifest.previousManifestHash !== cached.current.manifestHash) throw new Error("Stable manifest continuity mismatch");
          if (Date.parse(manifest.generatedAt) <= Date.parse(cached.current.manifest.generatedAt)) throw new Error("Stable manifest rollback detected");
        }
      }
      const registryCode = await this.reader.getCode(getAddress(this.config.registryAddress));
      if (!registryCode || registryCode === "0x") throw new Error("Dadieng Registry is not deployed");
      if (cached.current?.manifestHash === manifestHash) {
        const defenses = await Promise.all(manifest.versions.map((version, index) => {
          const bundle = cached.current!.bundles[index];
          if (!bundle) throw new Error("Cached stable artifact is missing");
          return this.verifyVersion(version, bundle);
        }));
        activate(defenses);
        return { status: "unchanged", manifestHash, activeVersions: this.versionIds(manifest) };
      }
      const bundles: DefenseBundle[] = [];
      const defenses: DefenseRule[] = [];
      for (const version of manifest.versions) {
        const bundle = verifyDefenseBundle(await this.fetcher.get(version.artifactUri) as DefenseBundle);
        bundles.push(bundle);
        defenses.push(await this.verifyVersion(version, bundle));
      }
      const next: ActivatedManifestSet = { manifestHash, manifest, bundles, activatedAt: this.now() };
      await this.cache.save({ current: next, ...(cached.current ? { previous: cached.current } : {}) });
      activate(defenses);
      return { status: "activated", manifestHash, activeVersions: this.versionIds(manifest) };
    } catch {
      cached = await this.cache.load().catch(() => ({}));
      if (this.failMode === "last-known-good" && cached.current) {
        try {
          await this.verifyManifestTrust(cached.current.manifest);
          const defenses = await Promise.all(cached.current.manifest.versions.map((version, index) => {
            const bundle = cached.current!.bundles[index];
            if (!bundle) throw new Error("Cached stable artifact is missing");
            return this.verifyLocalVersion(version, bundle);
          }));
          activate(defenses);
        } catch {
          throw new Error("Stable manifest synchronization failed");
        }
        return {
          status: "using-last-known-good",
          manifestHash: cached.current.manifestHash,
          activeVersions: this.versionIds(cached.current.manifest),
          errorCode: "MANIFEST_REFRESH_FAILED",
        };
      }
      if (this.failMode === "open") {
        return { status: "failed-open", manifestHash: null, activeVersions: [], errorCode: "MANIFEST_REFRESH_FAILED" };
      }
      throw new Error("Stable manifest synchronization failed");
    }
  }

  private versionIds(manifest: StableManifest) {
    return manifest.versions.map((version) => `${version.defenseId}@${version.version}`);
  }

  private async verifyVersion(version: StableManifest["versions"][number], input: DefenseBundle): Promise<DefenseRule> {
    const defense = this.verifyLocalVersion(version, input);
    const bundle = verifyDefenseBundle(input);
    const state = await this.reader.getVersion(
      getAddress(this.config.registryAddress),
      defenseVersionKey(version.defenseId, version.version),
    );
    if (state.status !== 3) throw new Error(`Defense ${version.defenseId}@${version.version} is not stable on Monad`);
    if (state.manifestHash.toLowerCase() !== sha256Commitment(bundle.manifestHash).toLowerCase()
      || state.artifactHash.toLowerCase() !== sha256Commitment(bundle.manifest.artifactHash).toLowerCase()) {
      throw new Error(`Monad commitment mismatch for ${version.defenseId}@${version.version}`);
    }
    return defense;
  }

  private verifyLocalVersion(version: StableManifest["versions"][number], input: DefenseBundle): DefenseRule {
    const bundle = verifyDefenseBundle(input);
    if (bundle.manifest.defenseId !== version.defenseId || bundle.manifest.version !== version.version
      || bundle.manifest.artifactHash !== version.artifactHash) throw new Error("Stable manifest artifact identity mismatch");
    if (!satisfiesSdkRange(this.config.sdkVersion, bundle.manifest.compatibility.sdk)
      || !bundle.manifest.compatibility.eventSchemas.includes(DADIENG_EVENT_SCHEMA_VERSION)
      || !this.config.adapters.some((adapter) => bundle.manifest.compatibility.adapters.includes(adapter))) {
      throw new Error(`Defense ${version.defenseId}@${version.version} is incompatible with this SDK`);
    }
    if (!runDefenseSuite(bundle).passed) throw new Error(`Shadow suite failed for ${version.defenseId}@${version.version}`);
    return loadDefenseBundle(bundle);
  }

  private async verifyManifestTrust(manifest: StableManifest): Promise<void> {
    const { signature, ...unsigned } = manifest;
    const signer = await recoverMessageAddress({
      message: stableManifestSigningMessage(unsigned),
      signature: signature as Hex,
    });
    if (!isAddressEqual(signer, getAddress(this.config.signerAddress))) throw new Error("Stable manifest signer mismatch");
    if (manifest.channel !== "stable" || manifest.chainId !== this.config.chainId
      || !isAddressEqual(getAddress(manifest.registryAddress), getAddress(this.config.registryAddress))) {
      throw new Error("Stable manifest network mismatch");
    }
  }
}
