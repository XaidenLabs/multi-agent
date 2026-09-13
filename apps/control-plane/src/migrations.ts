import { readFile } from "node:fs/promises";
import type { Pool } from "pg";

const migrations = [
  { version: "0001_control_plane", file: "./migrations/0001_control_plane.sql" },
  { version: "0002_chain_operations", file: "./migrations/0002_chain_operations.sql" },
  { version: "0003_validation_jobs", file: "./migrations/0003_validation_jobs.sql" },
  { version: "0004_stable_manifests", file: "./migrations/0004_stable_manifests.sql" },
] as const;

export async function migratePostgres(pool: Pick<Pool, "query">): Promise<void> {
  await pool.query("CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  for (const migration of migrations) {
    await pool.query("BEGIN");
    try {
      await pool.query("SELECT pg_advisory_xact_lock(731182019)");
      const applied = await pool.query<{ version: string }>("SELECT version FROM schema_migrations WHERE version = $1", [migration.version]);
      if (!applied.rowCount) {
        const sql = await readFile(new URL(migration.file, import.meta.url), "utf8");
        await pool.query(sql);
        await pool.query("INSERT INTO schema_migrations (version) VALUES ($1)", [migration.version]);
      }
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }
}
