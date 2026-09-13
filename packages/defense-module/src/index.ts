import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  defenseArtifactSchema,
  defenseManifestSchema,
  defenseSbomSchema,
  defenseTestSuiteSchema,
  type DefenseArtifact,
  type DefenseManifest,
  type DefenseRule,
  type DefenseSbom,
  type DefenseTestSuite,
} from "@dadieng/schemas";

export interface DefenseBundle {
  manifest: DefenseManifest;
  artifact: DefenseArtifact;
  sbom: DefenseSbom;
  suite: DefenseTestSuite;
}

export interface VerifiedDefenseBundle extends DefenseBundle {
  manifestHash: string;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .map(([key, child]) => [key, canonicalize(child)]),
    );
  }
  return value;
}

export interface DefenseSuiteCaseResult {
  caseId: string;
  expectedOutcome: DefenseTestSuite["cases"][number]["expectedOutcome"];
  actualOutcome: DefenseTestSuite["cases"][number]["expectedOutcome"];
  passed: boolean;
}

export interface DefenseSuiteResult {
  defenseId: string;
  version: string;
  passed: boolean;
  cases: DefenseSuiteCaseResult[];
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function contentHash(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

export function createDefenseBundle(
  manifest: Omit<DefenseManifest, "artifactHash" | "suiteHash" | "sbomHash">,
  artifact: DefenseArtifact,
  suite: DefenseTestSuite,
  sbom: DefenseSbom,
): DefenseBundle {
  return {
    manifest: defenseManifestSchema.parse({
      ...manifest,
      artifactHash: contentHash(artifact),
      suiteHash: contentHash(suite),
      sbomHash: contentHash(sbom),
    }),
    artifact: defenseArtifactSchema.parse(artifact),
    suite: defenseTestSuiteSchema.parse(suite),
    sbom: defenseSbomSchema.parse(sbom),
  };
}

export function verifyDefenseBundle(input: DefenseBundle): VerifiedDefenseBundle {
  const manifest = defenseManifestSchema.parse(input.manifest);
  const artifact = defenseArtifactSchema.parse(input.artifact);
  const suite = defenseTestSuiteSchema.parse(input.suite);
  const sbom = defenseSbomSchema.parse(input.sbom);

  if (manifest.runtime !== "dadieng-rules") {
    throw new Error(`Runtime ${manifest.runtime} requires an isolated executor and cannot load locally`);
  }
  if (manifest.entrypoint !== "artifact.json") {
    throw new Error("dadieng-rules bundles must use artifact.json as their entrypoint");
  }
  if (manifest.defenseId !== artifact.defenseId || manifest.defenseId !== suite.defenseId || manifest.defenseId !== sbom.defenseId) {
    throw new Error("Defense ID must match across manifest, artifact, suite, and SBOM");
  }
  if (contentHash(artifact) !== manifest.artifactHash) {
    throw new Error("Defense artifact hash mismatch");
  }
  if (contentHash(sbom) !== manifest.sbomHash) {
    throw new Error("Defense SBOM hash mismatch");
  }
  if (contentHash(suite) !== manifest.suiteHash) {
    throw new Error("Defense test-suite hash mismatch");
  }

  const declaredOutcomes = new Set(manifest.expectedOutcomes);
  for (const rule of artifact.rules) {
    if (!declaredOutcomes.has(rule.outcome)) {
      throw new Error(`Rule ${rule.ruleId} uses undeclared outcome ${rule.outcome}`);
    }
  }

  return { manifest, artifact, suite, sbom, manifestHash: contentHash(manifest) };
}

export function loadDefenseBundle(input: DefenseBundle): DefenseRule {
  const bundle = verifyDefenseBundle(input);

  const normalize = (value: string) => value
    .normalize("NFKC")
    .toLocaleLowerCase("en-US")
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, "")
    .replace(/[іΙ]/g, "i")
    .replace(/[аΑ]/g, "a")
    .replace(/[еΕ]/g, "e")
    .replace(/[оΟ]/g, "o")
    .replace(/[рΡ]/g, "p")
    .replace(/[сϹ]/g, "c")
    .replace(/[хΧ]/g, "x")
    .replace(/<[^>]{0,200}>/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  const textForms = (value: string): string[] => {
    const forms = new Set<string>();
    const add = (candidate: string) => {
      const normalized = normalize(candidate);
      forms.add(normalized);
      forms.add(normalized.replace(/[\p{P}\p{S}\s_]+/gu, ""));
    };
    add(value);
    try { add(decodeURIComponent(value)); } catch { /* malformed percent encoding is just ordinary content */ }
    for (const token of value.match(/[A-Za-z0-9+/]{20,}={0,2}/g) ?? []) {
      try {
        const decoded = Buffer.from(token, "base64").toString("utf8");
        const printable = [...decoded].filter((character) => /[\x20-\x7E\n\r\t]/.test(character)).length;
        if (decoded.length && printable / decoded.length > 0.85) add(decoded);
      } catch { /* invalid candidates cannot influence the decision */ }
    }
    return [...forms];
  };

  return {
    defenseId: bundle.manifest.defenseId,
    version: bundle.manifest.version,
    evaluate(event) {
      const candidateContent = textForms(event.content);
      for (const rule of bundle.artifact.rules) {
        if (!rule.stages.includes(event.stage) || !rule.trustZones.includes(event.source.trustZone)) continue;

        const matchesEveryGroup = rule.indicatorGroups.every((group) => group.some((indicator) => {
          const indicatorForms = textForms(indicator);
          return candidateContent.some((content) => indicatorForms.some((needle) => content.includes(needle)));
        }));
        if (!matchesEveryGroup) continue;

        return {
          outcome: event.policyContext.mode === "observe" && rule.outcome === "BLOCK" ? "OBSERVE" : rule.outcome,
          reasonCodes: rule.reasonCodes,
          matchedDefenseIds: [`${bundle.manifest.defenseId}@${bundle.manifest.version}`],
        };
      }
      return null;
    },
  };
}

export function runDefenseSuite(input: DefenseBundle): DefenseSuiteResult {
  const bundle = verifyDefenseBundle(input);
  const defense = loadDefenseBundle(bundle);
  const cases = bundle.suite.cases.map((testCase) => {
    const result = defense.evaluate({
      schemaVersion: "dadieng.event.v1",
      eventId: `suite:${testCase.caseId}`,
      timestamp: "1970-01-01T00:00:00.000Z",
      agent: { agentId: "dadieng.suite-runner", framework: "dadieng", sdkVersion: "0.1.0" },
      stage: testCase.stage,
      source: { type: "defense_suite", trustZone: testCase.trustZone },
      content: testCase.content,
      contentReferences: [{ type: "suite_case", fingerprint: contentHash(testCase.content) }],
      policyContext: { channel: "candidate", mode: "enforce" },
    });
    const actualOutcome = result?.outcome ?? "ALLOW";

    return {
      caseId: testCase.caseId,
      expectedOutcome: testCase.expectedOutcome,
      actualOutcome,
      passed: actualOutcome === testCase.expectedOutcome,
    };
  });

  return {
    defenseId: bundle.manifest.defenseId,
    version: bundle.manifest.version,
    passed: cases.every((testCase) => testCase.passed),
    cases,
  };
}

export async function readDefenseBundle(directory: string): Promise<DefenseBundle> {
  const [manifest, artifact, suite, sbom] = await Promise.all([
    readFile(join(directory, "manifest.json"), "utf8"),
    readFile(join(directory, "artifact.json"), "utf8"),
    readFile(join(directory, "suite.json"), "utf8"),
    readFile(join(directory, "sbom.json"), "utf8"),
  ]);

  return {
    manifest: JSON.parse(manifest) as DefenseManifest,
    artifact: JSON.parse(artifact) as DefenseArtifact,
    suite: JSON.parse(suite) as DefenseTestSuite,
    sbom: JSON.parse(sbom) as DefenseSbom,
  };
}
