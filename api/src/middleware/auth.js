import jwt from 'jsonwebtoken';

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  console.warn('[auth] JWT_SECRET not set — using ephemeral secret (tokens lost on restart)');
}
const RESOLVED_SECRET = SECRET || Math.random().toString(36).slice(2);

export function signToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    RESOLVED_SECRET,
    { expiresIn: '12h' },
  );
}

export function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    const claims = jwt.verify(token, RESOLVED_SECRET);
    req.user = { id: claims.sub, username: claims.username, role: claims.role };
    next();
  } catch (err) {
    res.status(401).json({ error: 'invalid token' });
  }
}

export function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  next();
}
