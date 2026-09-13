import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createMcpBoundaryBundle } from "./mcp-boundary.js";

const outputDirectory = resolve(process.cwd(), "../../defenses/mcp-boundary");
const bundle = createMcpBoundaryBundle();

await mkdir(outputDirectory, { recursive: true });
await Promise.all([
  writeFile(resolve(outputDirectory, "manifest.json"), `${JSON.stringify(bundle.manifest, null, 2)}\n`),
  writeFile(resolve(outputDirectory, "artifact.json"), `${JSON.stringify(bundle.artifact, null, 2)}\n`),
  writeFile(resolve(outputDirectory, "suite.json"), `${JSON.stringify(bundle.suite, null, 2)}\n`),
  writeFile(resolve(outputDirectory, "sbom.json"), `${JSON.stringify(bundle.sbom, null, 2)}\n`),
]);

console.log(`Wrote ${bundle.manifest.defenseId}@${bundle.manifest.version} to ${outputDirectory}`);
