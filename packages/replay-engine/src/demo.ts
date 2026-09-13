import { readFile } from "node:fs/promises";
import { createMcpReferenceReport } from "./mcp-reference.js";

const lockfile = await readFile(new URL("../../../pnpm-lock.yaml", import.meta.url));
console.log(JSON.stringify(createMcpReferenceReport(lockfile), null, 2));
