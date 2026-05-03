import { Router } from 'express';
import { v4 as uuid } from 'uuid';
import { requireAuth } from '../middleware/auth.js';
import { db, audit } from '../db/index.js';
import { callWorker } from '../services/workerClient.js';

export const techniquesRouter = Router();
export const runsRouter = Router();

techniquesRouter.use(requireAuth);
runsRouter.use(requireAuth);

// ----- catalog -----
techniquesRouter.get('/', async (_req, res, next) => {
  try {
    const data = await callWorker('/techniques', null, { method: 'GET' });
    res.json(data);
  } catch (err) { next(err); }
});

techniquesRouter.get('/:id', async (req, res, next) => {
  try {
    const data = await callWorker(`/techniques/${encodeURIComponent(req.params.id)}`, null, { method: 'GET' });
    res.json(data);
  } catch (err) { next(err); }
});

// ----- run -----
techniquesRouter.post('/:id/run', async (req, res, next) => {
  try {
    const { test_name, timeout } = req.body || {};
    if (!test_name) return res.status(400).json({ error: 'test_name required' });

    const result = await callWorker('/technique/run', {
      technique_id: req.params.id,
      test_name,
      timeout,
    });

    const id = uuid();
    db.prepare(`
      INSERT INTO technique_runs
        (id, user_id, technique_id, test_name, executor, command,
         exit_code, duration_ms, stdout, stderr, truncated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      req.user.id,
      result.technique_id,
      result.test_name,
      result.executor,
      result.command,
      result.exit_code,
      result.duration_ms,
      result.stdout || '',
      result.stderr || '',
      result.truncated ? 1 : 0,
    );

    audit(req.user.id, 'technique_run', {
      run_id: id,
      technique_id: result.technique_id,
      test_name: result.test_name,
      exit_code: result.exit_code,
    }, req.ip);

    res.json({ run_id: id, ...result });
  } catch (err) { next(err); }
});

// ----- script -----
techniquesRouter.post('/:id/script', async (req, res, next) => {
  try {
    const { test_name } = req.body || {};
    if (!test_name) return res.status(400).json({ error: 'test_name required' });
    const data = await callWorker('/technique/script', {
      technique_id: req.params.id,
      test_name,
    });
    audit(req.user.id, 'technique_script', {
      technique_id: req.params.id,
      test_name,
      filename: data.filename,
    }, req.ip);
    res.json(data);
  } catch (err) { next(err); }
});

// ----- run history -----
runsRouter.get('/', (req, res) => {
  const rows = db.prepare(`
    SELECT id, technique_id, test_name, executor, exit_code, duration_ms,
           truncated, created_at
    FROM technique_runs
    WHERE user_id = ?
    ORDER BY datetime(created_at) DESC
    LIMIT 100
  `).all(req.user.id);
  res.json({ runs: rows });
});

runsRouter.get('/:id', (req, res) => {
  const row = db.prepare(`
    SELECT * FROM technique_runs WHERE id = ? AND user_id = ?
  `).get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row);
});
