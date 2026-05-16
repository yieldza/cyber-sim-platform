-- Schema for CSP API gateway (SQLite)

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'analyst',
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS artifacts (
  id          TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id),
  file_type   TEXT NOT NULL,
  filename    TEXT NOT NULL,
  size        INTEGER NOT NULL,
  md5         TEXT NOT NULL,
  sha1        TEXT NOT NULL,
  sha256      TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  source_op   TEXT NOT NULL,        -- generate / mutate / convert
  parent_id   TEXT REFERENCES artifacts(id),
  metadata    TEXT,                 -- JSON
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_artifacts_user ON artifacts(user_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);

CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER REFERENCES users(id),
  action      TEXT NOT NULL,
  detail      TEXT,                 -- JSON
  ip          TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at);

-- Milestone B — ATT&CK runs persisted from worker output
CREATE TABLE IF NOT EXISTS technique_runs (
  id            TEXT PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id),
  technique_id  TEXT NOT NULL,
  test_name     TEXT NOT NULL,
  executor      TEXT NOT NULL,
  command       TEXT NOT NULL,
  exit_code     INTEGER,
  duration_ms   INTEGER,
  stdout        TEXT,
  stderr        TEXT,
  truncated     INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_runs_user ON technique_runs(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_runs_tech ON technique_runs(technique_id);

-- Milestone C — Caldera-style HTTP-polling agents

CREATE TABLE IF NOT EXISTS agent_enroll_tokens (
  token        TEXT PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id),
  label        TEXT,
  expires_at   TEXT NOT NULL,
  used_by      TEXT,                    -- agent_id once consumed
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agents (
  id              TEXT PRIMARY KEY,
  user_id         INTEGER NOT NULL REFERENCES users(id),
  hostname        TEXT,
  platform        TEXT,                 -- linux | macos | windows
  agent_version   TEXT,
  internal_ip     TEXT,
  external_ip     TEXT,
  secret_hash     TEXT NOT NULL,        -- bcrypt(secret)
  beacon_count    INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'active',  -- active | killed
  last_seen       TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_agents_user ON agents(user_id);

CREATE TABLE IF NOT EXISTS agent_tasks (
  id              TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL REFERENCES agents(id),
  created_by      INTEGER NOT NULL REFERENCES users(id),
  technique_id    TEXT NOT NULL,
  test_name       TEXT NOT NULL,
  executor        TEXT NOT NULL,
  command         TEXT NOT NULL,        -- frozen at queue time from catalog
  cleanup         TEXT,
  timeout_sec     INTEGER NOT NULL DEFAULT 15,
  status          TEXT NOT NULL DEFAULT 'pending',  -- pending|sent|done|error|timeout
  exit_code       INTEGER,
  duration_ms     INTEGER,
  stdout          TEXT,
  stderr          TEXT,
  truncated       INTEGER NOT NULL DEFAULT 0,
  sent_at         TEXT,
  finished_at     TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tasks_agent ON agent_tasks(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_user  ON agent_tasks(created_by, created_at);

-- Coverage matrix — manual detection-result marking per technique
CREATE TABLE IF NOT EXISTS coverage_results (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id           INTEGER NOT NULL REFERENCES users(id),
  technique_id      TEXT NOT NULL,
  test_name         TEXT,
  detection_status  TEXT NOT NULL DEFAULT 'untested',  -- detected | not_detected | partial | untested
  edr_product       TEXT,                               -- e.g. "Cortex XDR", "CrowdStrike"
  alert_name        TEXT,                               -- name of alert/BTP rule that fired
  notes             TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_coverage_user ON coverage_results(user_id, technique_id);
CREATE INDEX IF NOT EXISTS idx_coverage_tech ON coverage_results(technique_id);
