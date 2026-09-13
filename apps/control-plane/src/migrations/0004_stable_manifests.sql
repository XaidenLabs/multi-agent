CREATE TABLE IF NOT EXISTS stable_manifests (
  manifest_hash text PRIMARY KEY,
  channel text NOT NULL,
  previous_manifest_hash text,
  lineage_parent text NOT NULL,
  manifest jsonb NOT NULL,
  generated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  CHECK (expires_at > generated_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS stable_manifests_continuity_idx
  ON stable_manifests (channel, lineage_parent);

CREATE INDEX IF NOT EXISTS stable_manifests_latest_idx
  ON stable_manifests (channel, generated_at DESC, manifest_hash DESC);
