CREATE TABLE IF NOT EXISTS validation_jobs (
  job_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  replay_id text NOT NULL UNIQUE REFERENCES replay_runs(replay_id),
  defense_version_id text NOT NULL REFERENCES defense_versions(defense_version_id),
  version_key text NOT NULL,
  chain_id integer NOT NULL CHECK (chain_id > 0),
  registry_address text NOT NULL,
  validation_address text NOT NULL,
  bundle jsonb NOT NULL,
  environment jsonb NOT NULL,
  thresholds jsonb,
  canonical_report_hash text NOT NULL,
  status text NOT NULL CHECK (status IN ('open', 'claimed', 'submitted')),
  claimed_by text,
  validator_agent_id text,
  validator_address text,
  claim_expires_at timestamptz,
  report jsonb,
  attestation jsonb,
  transaction_hash text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK ((status = 'open' AND claimed_by IS NULL AND validator_agent_id IS NULL AND validator_address IS NULL
      AND claim_expires_at IS NULL AND report IS NULL AND attestation IS NULL AND transaction_hash IS NULL)
    OR (status = 'claimed' AND claimed_by IS NOT NULL AND validator_agent_id IS NOT NULL AND validator_address IS NOT NULL
      AND claim_expires_at IS NOT NULL AND report IS NULL AND attestation IS NULL AND transaction_hash IS NULL)
    OR (status = 'submitted' AND claimed_by IS NOT NULL AND validator_agent_id IS NOT NULL AND validator_address IS NOT NULL
      AND claim_expires_at IS NULL AND report IS NOT NULL AND attestation IS NOT NULL AND transaction_hash IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS validation_jobs_available_idx
  ON validation_jobs (tenant_id, created_at, job_id)
  WHERE status IN ('open', 'claimed');
