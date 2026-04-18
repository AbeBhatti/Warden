PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  scope_ceiling TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  task TEXT NOT NULL,
  agent_identity TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  status TEXT NOT NULL,
  environment TEXT NOT NULL DEFAULT 'production'
);

CREATE TABLE IF NOT EXISTS capabilities (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  cap_type TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  justification TEXT,
  granted_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  revocation_reason TEXT,
  FOREIGN KEY (run_id) REFERENCES runs(id),
  FOREIGN KEY (credential_id) REFERENCES credentials(id)
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  run_id TEXT,
  capability_id TEXT,
  event_type TEXT NOT NULL,
  tool TEXT,
  args_redacted TEXT,
  outcome TEXT NOT NULL,
  detail TEXT,
  duration_ms INTEGER,
  prev_hash TEXT,
  event_hash TEXT
);

CREATE TABLE IF NOT EXISTS audit_chain_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_event_id INTEGER NOT NULL,
  last_event_hash TEXT NOT NULL,
  genesis_hash TEXT NOT NULL,
  chain_started_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_run_ts ON events (run_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_caps_run ON capabilities (run_id);
CREATE INDEX IF NOT EXISTS idx_caps_active ON capabilities (revoked_at, expires_at);

CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version INTEGER NOT NULL,
  yaml_body TEXT NOT NULL,
  active INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
