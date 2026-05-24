import Database from 'better-sqlite3';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import bcrypt from 'bcryptjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

const DB_PATH = process.env.DB_PATH || join(process.cwd(), 'data', 'csp.sqlite');

export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

const schema = readFileSync(join(__dirname, 'schema.sql'), 'utf8');
db.exec(schema);

// ─── Schema migrations ────────────────────────────────────────────────────
// CREATE TABLE IF NOT EXISTS does NOT alter pre-existing tables. Deployments
// that started on v0.1.0 / v0.2.0 will have older shapes for `agents` and
// `agent_tasks`, missing the v0.3.x columns referenced by the agent C2
// channel — that path was the root cause of the "500 Internal Server Error"
// reported on first beacon. We patch in additive ALTER TABLE statements
// here; SQLite ignores them for already-correct columns.
function ensureColumn(table, name, ddl) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    if (!cols.find(c => c.name === name)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
      console.log(`[db migrate] ${table}.${name} added`);
    }
  } catch (e) {
    console.warn(`[db migrate] cannot add ${table}.${name}: ${e.message}`);
  }
}

// agents — v0.1.0 had only id/hostname/platform/user_id/created_at/last_seen
ensureColumn('agents', 'agent_version', 'agent_version TEXT');
ensureColumn('agents', 'internal_ip',   'internal_ip TEXT');
ensureColumn('agents', 'external_ip',   'external_ip TEXT');
ensureColumn('agents', 'secret_hash',   'secret_hash TEXT');
ensureColumn('agents', 'beacon_count',  'beacon_count INTEGER NOT NULL DEFAULT 0');
ensureColumn('agents', 'status',        "status TEXT NOT NULL DEFAULT 'active'");

// agent_tasks — v0.1.0 only had id/agent_id/technique_id/status/result/created_at/updated_at
ensureColumn('agent_tasks', 'created_by',  'created_by INTEGER');
ensureColumn('agent_tasks', 'test_name',   'test_name TEXT');
ensureColumn('agent_tasks', 'executor',    'executor TEXT');
ensureColumn('agent_tasks', 'command',     'command TEXT');
ensureColumn('agent_tasks', 'cleanup',     'cleanup TEXT');
ensureColumn('agent_tasks', 'timeout_sec', 'timeout_sec INTEGER NOT NULL DEFAULT 15');
ensureColumn('agent_tasks', 'exit_code',   'exit_code INTEGER');
ensureColumn('agent_tasks', 'duration_ms', 'duration_ms INTEGER');
ensureColumn('agent_tasks', 'stdout',      'stdout TEXT');
ensureColumn('agent_tasks', 'stderr',      'stderr TEXT');
ensureColumn('agent_tasks', 'truncated',   'truncated INTEGER NOT NULL DEFAULT 0');
ensureColumn('agent_tasks', 'sent_at',     'sent_at TEXT');
ensureColumn('agent_tasks', 'finished_at', 'finished_at TEXT');

// coverage_results — v0.7.0 adds `source` column so webhook-marked rows
// can be distinguished from operator-marked rows in the UI / audit log.
ensureColumn('coverage_results', 'source', 'source TEXT');

// Bootstrap admin user from env on first start
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;
if (ADMIN_USER && ADMIN_PASS) {
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(ADMIN_USER);
  if (!existing) {
    const hash = bcrypt.hashSync(ADMIN_PASS, 12);
    db.prepare(
      'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
    ).run(ADMIN_USER, hash, 'admin');
    console.log(`[db] bootstrapped admin user: ${ADMIN_USER}`);
  }
}

export function audit(userId, action, detail, ip) {
  db.prepare(
    'INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)'
  ).run(userId ?? null, action, detail ? JSON.stringify(detail) : null, ip ?? null);
}
