import { resolve } from "node:path";
import { Pool } from "pg";
import { FileSystemPrivateObjectStore } from "./object-store.js";
import { PostgresControlPlaneRepository } from "./repository.js";
import { ControlPlaneService } from "./service.js";

const databaseUrl = process.env.DATABASE_URL;
const objectRoot = process.env.DADIENG_OBJECT_ROOT;
if (!databaseUrl) throw new Error("DATABASE_URL is required");
if (!objectRoot) throw new Error("DADIENG_OBJECT_ROOT is required");
const retentionDays = Number.parseInt(process.env.EVIDENCE_RETENTION_DAYS ?? "30", 10);
if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 30) {
  throw new Error("EVIDENCE_RETENTION_DAYS must be between 1 and 30");
}

const pool = new Pool({
  connectionString: databaseUrl,
  ...(process.env.DATABASE_SSL === "require" ? { ssl: { rejectUnauthorized: true } } : {}),
});
const service = new ControlPlaneService(
  new PostgresControlPlaneRepository(pool),
  undefined,
  undefined,
  new FileSystemPrivateObjectStore(resolve(objectRoot)),
);
const cutoff = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
let deleted = 0;
try {
  while (true) {
    const batch = await service.purgeEvidenceBefore(cutoff, 100);
    deleted += batch;
    if (batch < 100) break;
  }
  console.log(`Deleted ${deleted} expired evidence object${deleted === 1 ? "" : "s"}`);
} finally {
  await pool.end();
}
