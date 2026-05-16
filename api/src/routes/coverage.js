import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { db, audit } from '../db/index.js';
import { callWorker } from '../services/workerClient.js';

export const coverageRouter = Router();
coverageRouter.use(requireAuth);

// GET /api/coverage — aggregate coverage matrix
// Combines: catalog techniques + technique_runs + agent_tasks + manual coverage_results
coverageRouter.get('/', async (req, res, next) => {
  try {
    // Fetch full catalog from worker
    const catalog = await callWorker('/techniques', null, { method: 'GET' });
    const techniques = catalog.techniques || catalog;

    // Get all runs for this user
    const runs = db.prepare(`
      SELECT technique_id, test_name, exit_code
      FROM technique_runs
      WHERE user_id = ?
      ORDER BY datetime(created_at) DESC
    `).all(req.user.id);

    // Get all agent task results for this user
    const agentTasks = db.prepare(`
      SELECT technique_id, test_name, exit_code, status
      FROM agent_tasks
      WHERE created_by = ? AND status = 'done'
      ORDER BY datetime(created_at) DESC
    `).all(req.user.id);

    // Get manual coverage markings
    const manual = db.prepare(`
      SELECT technique_id, test_name, detection_status, edr_product, alert_name, notes, updated_at
      FROM coverage_results
      WHERE user_id = ?
      ORDER BY datetime(updated_at) DESC
    `).all(req.user.id);

    // Build coverage map
    const coverageMap = {};

    for (const t of techniques) {
      const tid = t.id;
      coverageMap[tid] = {
        id: tid,
        name: t.name,
        tactic: t.tactic,
        platforms: t.platforms,
        tests: (t.tests || []).map(test => test.name),
        run_count: 0,
        last_run_exit: null,
        agent_run_count: 0,
        detection_status: 'untested', // detected | not_detected | partial | untested
        edr_product: null,
        alert_name: null,
        notes: null,
      };
    }

    // Aggregate runs
    for (const r of runs) {
      if (coverageMap[r.technique_id]) {
        coverageMap[r.technique_id].run_count++;
        if (coverageMap[r.technique_id].last_run_exit === null) {
          coverageMap[r.technique_id].last_run_exit = r.exit_code;
        }
      }
    }

    // Aggregate agent tasks
    for (const t of agentTasks) {
      if (coverageMap[t.technique_id]) {
        coverageMap[t.technique_id].agent_run_count++;
      }
    }

    // Override with manual markings (most recent wins)
    const seen = new Set();
    for (const m of manual) {
      if (!seen.has(m.technique_id) && coverageMap[m.technique_id]) {
        coverageMap[m.technique_id].detection_status = m.detection_status;
        coverageMap[m.technique_id].edr_product = m.edr_product;
        coverageMap[m.technique_id].alert_name = m.alert_name;
        coverageMap[m.technique_id].notes = m.notes;
        seen.add(m.technique_id);
      }
    }

    // Compute summary stats
    const all = Object.values(coverageMap);
    const summary = {
      total: all.length,
      detected: all.filter(t => t.detection_status === 'detected').length,
      not_detected: all.filter(t => t.detection_status === 'not_detected').length,
      partial: all.filter(t => t.detection_status === 'partial').length,
      untested: all.filter(t => t.detection_status === 'untested').length,
      tested_count: all.filter(t => t.run_count > 0 || t.agent_run_count > 0).length,
    };

    // Group by tactic
    const byTactic = {};
    for (const t of all) {
      if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
      byTactic[t.tactic].push(t);
    }

    res.json({ summary, by_tactic: byTactic, techniques: coverageMap });
  } catch (err) { next(err); }
});

// PUT /api/coverage/:technique_id — set detection result for a technique
coverageRouter.put('/:technique_id', (req, res) => {
  const { technique_id } = req.params;
  const { detection_status, edr_product, alert_name, notes, test_name } = req.body || {};

  const valid = ['detected', 'not_detected', 'partial', 'untested'];
  if (!detection_status || !valid.includes(detection_status)) {
    return res.status(400).json({ error: `detection_status must be one of: ${valid.join(', ')}` });
  }

  // Upsert — one row per user+technique (latest wins)
  const existing = db.prepare(`
    SELECT id FROM coverage_results
    WHERE user_id = ? AND technique_id = ?
    ORDER BY datetime(updated_at) DESC LIMIT 1
  `).get(req.user.id, technique_id);

  if (existing) {
    db.prepare(`
      UPDATE coverage_results
      SET detection_status = ?, edr_product = ?, alert_name = ?, notes = ?, test_name = ?,
          updated_at = datetime('now')
      WHERE id = ?
    `).run(detection_status, edr_product || null, alert_name || null, notes || null, test_name || null, existing.id);
  } else {
    db.prepare(`
      INSERT INTO coverage_results (user_id, technique_id, test_name, detection_status, edr_product, alert_name, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(req.user.id, technique_id, test_name || null, detection_status, edr_product || null, alert_name || null, notes || null);
  }

  audit(req.user.id, 'coverage_mark', { technique_id, detection_status, edr_product }, req.ip);

  res.json({ ok: true, technique_id, detection_status });
});

// DELETE /api/coverage/:technique_id — reset detection result
coverageRouter.delete('/:technique_id', (req, res) => {
  db.prepare(`
    DELETE FROM coverage_results WHERE user_id = ? AND technique_id = ?
  `).run(req.user.id, req.params.technique_id);

  res.json({ ok: true, technique_id: req.params.technique_id, detection_status: 'untested' });
});
