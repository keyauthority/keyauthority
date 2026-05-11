BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config JSONB NOT NULL,
    software_key BYTEA,
    environment TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()

    --config_hash BYTEA GENERATED ALWAYS AS (digest(config::text, 'sha256')) STORED,
    --software_key_hash BYTEA GENERATED ALWAYS AS (digest(software_key, 'sha256')) STORED,
    --CONSTRAINT unique_config UNIQUE (config_hash),
    --CONSTRAINT unique_software_key UNIQUE (software_key_hash)
);

CREATE TABLE IF NOT EXISTS signers (
  name TEXT PRIMARY KEY,
  private_key_id UUID REFERENCES keys(id),
  config JSONB NOT NULL,
  ca_chain BYTEA,
  crl BYTEA,
  updated_at TIMESTAMPTZ DEFAULT now(),

  CONSTRAINT unique_private_key UNIQUE (private_key_id)
);

CREATE TABLE IF NOT EXISTS secrets (
  name TEXT PRIMARY KEY,
  data BYTEA,
  encryption_key_id UUID REFERENCES keys(id),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS certs (
  serial TEXT PRIMARY KEY,
  signer_name TEXT REFERENCES signers(name),
  cn TEXT,
  sans TEXT[],
  der BYTEA NOT NULL,
  not_before TIMESTAMPTZ,
  not_after TIMESTAMPTZ,
  revoked BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  entry JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_requests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  created_at TIMESTAMPTZ DEFAULT now(),
  token_info JSONB NOT NULL,
  private_body BOOLEAN DEFAULT TRUE, -- whether the body can be viewed by approvers
  method TEXT NOT NULL,
  url TEXT NOT NULL,
  encrypted_token BYTEA,
  encrypted_body BYTEA
);

CREATE TABLE IF NOT EXISTS acme_accounts (
  uri TEXT PRIMARY KEY,
  public_key_jwk JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

COMMIT;