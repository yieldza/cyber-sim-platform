import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { db } from '../db/index.js';

const ENROLL_TOKEN_TTL_HOURS = 4;

export function generateEnrollToken(userId, label) {
  const token = 'ent_' + crypto.randomBytes(24).toString('hex');
  const expiresAt = new Date(Date.now() + ENROLL_TOKEN_TTL_HOURS * 3600_000)
    .toISOString()
    .replace('T', ' ')
    .slice(0, 19);
  db.prepare(`
    INSERT INTO agent_enroll_tokens (token, user_id, label, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(token, userId, label || null, expiresAt);
  return { token, expires_at: expiresAt };
}

export function consumeEnrollToken(token, agentId) {
  const row = db.prepare('SELECT * FROM agent_enroll_tokens WHERE token = ?').get(token);
  if (!row) return null;
  if (row.used_by) return null;
  if (new Date(row.expires_at + 'Z') < new Date()) return null;
  db.prepare('UPDATE agent_enroll_tokens SET used_by = ? WHERE token = ?').run(agentId, token);
  return row;
}

export function generateAgentSecret() {
  return 'as_' + crypto.randomBytes(32).toString('hex');
}

export function hashAgentSecret(secret) {
  return bcrypt.hashSync(secret, 10);
}

export function verifyAgentSecret(secret, hash) {
  try {
    return bcrypt.compareSync(secret, hash);
  } catch {
    return false;
  }
}

/** Express middleware — agent identifies via X-Agent-Id + X-Agent-Secret. */
export function requireAgent(req, res, next) {
  const id = req.headers['x-agent-id'];
  const secret = req.headers['x-agent-secret'];
  if (!id || !secret) return res.status(401).json({ error: 'agent credentials required' });
  const agent = db.prepare('SELECT * FROM agents WHERE id = ? AND status = "active"').get(id);
  if (!agent || !verifyAgentSecret(secret, agent.secret_hash)) {
    return res.status(401).json({ error: 'invalid agent credentials' });
  }
  req.agent = agent;
  next();
}
