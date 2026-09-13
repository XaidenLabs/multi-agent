CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS threat_receipts (
  receipt_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  deduplication_key text NOT NULL,
  public_receipt jsonb NOT NULL,
  evidence_object_uri text,
  evidence_hash text NOT NULL,
  evidence_size_bytes integer,
  evidence_stored_at timestamptz,
  evidence_deleted_at timestamptz,
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, deduplication_key),
  CHECK (evidence_size_bytes IS NULL OR evidence_size_bytes >= 0)
);

CREATE INDEX IF NOT EXISTS threat_receipts_retention_idx
  ON threat_receipts (evidence_stored_at)
  WHERE evidence_object_uri IS NOT NULL;

CREATE TABLE IF NOT EXISTS defenses (
  defense_id text PRIMARY KEY,
  name text NOT NULL,
  author_agent_id text NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS defense_versions (
  defense_version_id text PRIMARY KEY,
  defense_id text NOT NULL REFERENCES defenses(defense_id),
  bundle jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('candidate')),
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS replay_runs (
  replay_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  request jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
  report jsonb,
  error_code text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK ((status = 'completed' AND report IS NOT NULL AND error_code IS NULL)
    OR (status = 'failed' AND report IS NULL AND error_code IS NOT NULL)
    OR (status IN ('queued', 'running') AND report IS NULL AND error_code IS NULL))
);

CREATE INDEX IF NOT EXISTS replay_runs_queue_idx ON replay_runs (created_at, replay_id) WHERE status = 'queued';

CREATE TABLE IF NOT EXISTS idempotency_keys (
  storage_key text PRIMARY KEY,
  request_hash text NOT NULL,
  claim_token text NOT NULL,
  claim_expires_at timestamptz NOT NULL,
  response_status integer,
  response_body jsonb,
  response_headers jsonb,
  created_at timestamptz NOT NULL,
  completed_at timestamptz,
  CHECK ((response_status IS NULL AND response_body IS NULL AND response_headers IS NULL AND completed_at IS NULL)
    OR (response_status IS NOT NULL AND response_body IS NOT NULL AND response_headers IS NOT NULL AND completed_at IS NOT NULL))
);
