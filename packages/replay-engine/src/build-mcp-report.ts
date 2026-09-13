import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createMcpReferenceReport } from "./mcp-reference.js";

const repositoryRoot = resolve(process.cwd(), "../..");
const lockfile = await readFile(resolve(repositoryRoot, "pnpm-lock.yaml"));
const outputDirectory = resolve(repositoryRoot, "replays/mcp-boundary");
const report = createMcpReferenceReport(lockfile);

await mkdir(outputDirectory, { recursive: true });
await writeFile(resolve(outputDirectory, "report.json"), `${JSON.stringify(report, null, 2)}\n`);

console.log(`Wrote ${report.runId} to ${outputDirectory}`);
