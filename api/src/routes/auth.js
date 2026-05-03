import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { db, audit } from '../db/index.js';
import { signToken, requireAuth, requireAdmin } from '../middleware/auth.js';

export const authRouter = Router();

authRouter.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    audit(null, 'login_failed', { username }, req.ip);
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = signToken(user);
  audit(user.id, 'login', null, req.ip);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

authRouter.get('/me', requireAuth, (req, res) => res.json({ user: req.user }));

authRouter.post('/users', requireAuth, requireAdmin, (req, res) => {
  const { username, password, role = 'analyst' } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!['admin', 'analyst'].includes(role)) return res.status(400).json({ error: 'invalid role' });
  try {
    const hash = bcrypt.hashSync(password, 12);
    const result = db
      .prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
      .run(username, hash, role);
    audit(req.user.id, 'create_user', { username, role }, req.ip);
    res.json({ id: result.lastInsertRowid, username, role });
  } catch (err) {
    if (String(err).includes('UNIQUE')) return res.status(409).json({ error: 'username taken' });
    throw err;
  }
});
