import { Pool } from "pg";
import { migratePostgres } from "./migrations.js";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required");
const pool = new Pool({
  connectionString: databaseUrl,
  ...(process.env.DATABASE_SSL === "require" ? { ssl: { rejectUnauthorized: true } } : {}),
});
try {
  await migratePostgres(pool);
  console.log("Dadieng database migrations are current");
} finally {
  await pool.end();
}
