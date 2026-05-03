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
