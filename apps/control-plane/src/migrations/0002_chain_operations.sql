CREATE TABLE IF NOT EXISTS chain_operations (
  operation_id text PRIMARY KEY,
  signer_slot smallint NOT NULL DEFAULT 1 CHECK (signer_slot = 1),
  deduplication_key text NOT NULL UNIQUE,
  tenant_id text NOT NULL,
  operation_kind text NOT NULL CHECK (operation_kind IN (
    'register-defense', 'publish-version', 'publish-replay', 'publish-receipt',
    'submit-attestation', 'promote-version', 'quarantine-version', 'revoke-version', 'commit-usage-batch'
  )),
  payload jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('queued', 'prepared', 'submitted', 'confirmed', 'failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL,
  prepared_transaction_hash text,
  serialized_transaction text,
  transaction_hash text,
  block_number numeric(78, 0),
  confirmations integer CHECK (confirmations IS NULL OR confirmations >= 1),
  error_code text,
  claim_token text,
  claim_expires_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK ((claim_token IS NULL) = (claim_expires_at IS NULL)),
  CHECK ((status = 'queued' AND prepared_transaction_hash IS NULL AND serialized_transaction IS NULL AND transaction_hash IS NULL)
    OR (status = 'prepared' AND prepared_transaction_hash IS NOT NULL AND serialized_transaction IS NOT NULL AND transaction_hash IS NULL)
    OR (status = 'submitted' AND prepared_transaction_hash IS NOT NULL AND serialized_transaction IS NOT NULL AND transaction_hash IS NOT NULL)
    OR (status = 'confirmed' AND transaction_hash IS NOT NULL AND block_number IS NOT NULL AND confirmations IS NOT NULL AND error_code IS NULL)
    OR (status = 'failed' AND error_code IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS chain_operations_work_idx
  ON chain_operations (next_attempt_at, created_at, operation_id)
  WHERE status IN ('queued', 'prepared', 'submitted');

CREATE UNIQUE INDEX IF NOT EXISTS chain_operations_single_signer_claim_idx
  ON chain_operations (signer_slot)
  WHERE claim_token IS NOT NULL;
