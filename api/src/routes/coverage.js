import { Router } from 'express';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { requireAuth } from '../middleware/auth.js';
import { db, audit } from '../db/index.js';
import { callWorker } from '../services/workerClient.js';

export const coverageRouter = Router();
// Webhook receiver is mounted as a *separate* router because it does NOT
// take a JWT — it authenticates via the per-user webhook token header.
// Without this split, requireAuth would 401 every SIEM POST.
export const coverageWebhookRouter = Router();

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

// GET /api/coverage/export?format=csv|json — full matrix as a downloadable
// file. Useful for sharing with leadership or pasting into an existing
// detection-coverage spreadsheet.
//
// Route ordering note: this must be registered *before* any catch-all
// like '/:technique_id', else Express would route 'export' as a technique_id.
// (We're declaring it after, so it works because we use a literal segment
//  — Express tries literal matches before parameterised, but to be safe
//  the order below is fine because '/export' would match GET only and
//  '/:technique_id' is PUT/DELETE.)
coverageRouter.get('/export', async (req, res, next) => {
  try {
    const fmt = String(req.query.format || 'csv').toLowerCase();
    if (!['csv', 'json'].includes(fmt)) {
      return res.status(400).json({ error: "format must be 'csv' or 'json'" });
    }

    // Reuse the same aggregation the dashboard does so the export is the
    // same numbers operators see in the UI — single source of truth.
    const catalog = await callWorker('/techniques', null, { method: 'GET' });
    const techniques = catalog.techniques || catalog;

    const runs = db.prepare(`
      SELECT technique_id, MAX(created_at) AS last_run_at, COUNT(*) AS run_count
      FROM technique_runs WHERE user_id = ?
      GROUP BY technique_id
    `).all(req.user.id);
    const runMap = Object.fromEntries(runs.map(r => [r.technique_id, r]));

    const agentRuns = db.prepare(`
      SELECT technique_id, MAX(finished_at) AS last_run_at, COUNT(*) AS run_count
      FROM agent_tasks WHERE created_by = ? AND status = 'done'
      GROUP BY technique_id
    `).all(req.user.id);
    const agentMap = Object.fromEntries(agentRuns.map(r => [r.technique_id, r]));

    const manual = db.prepare(`
      SELECT technique_id, detection_status, edr_product, alert_name, notes, updated_at
      FROM coverage_results
      WHERE user_id = ?
    `).all(req.user.id);
    const manualMap = Object.fromEntries(manual.map(m => [m.technique_id, m]));

    const rows = techniques.map(t => {
      const r = runMap[t.id] || {};
      const a = agentMap[t.id] || {};
      const m = manualMap[t.id] || {};
      return {
        technique_id: t.id,
        name: t.name,
        tactic: t.tactic,
        platforms: (t.platforms || []).join('|'),
        test_count: (t.tests || []).length,
        worker_run_count: r.run_count || 0,
        worker_last_run_at: r.last_run_at || '',
        agent_run_count: a.run_count || 0,
        agent_last_run_at: a.last_run_at || '',
        detection_status: m.detection_status || 'untested',
        edr_product: m.edr_product || '',
        alert_name: m.alert_name || '',
        notes: (m.notes || '').replace(/[\r\n]+/g, ' ').trim(),
        marked_at: m.updated_at || '',
      };
    });

    audit(req.user.id, 'coverage_export', { format: fmt, count: rows.length }, req.ip);

    if (fmt === 'json') {
      res.setHeader('content-type', 'application/json');
      res.setHeader('content-disposition',
        `attachment; filename="csp-coverage-${new Date().toISOString().slice(0,10)}.json"`);
      return res.send(JSON.stringify({ exported_at: new Date().toISOString(), rows }, null, 2));
    }

    // CSV — RFC 4180-ish (quote fields containing comma/quote/newline).
    const cols = [
      'technique_id', 'name', 'tactic', 'platforms', 'test_count',
      'worker_run_count', 'worker_last_run_at',
      'agent_run_count',  'agent_last_run_at',
      'detection_status', 'edr_product', 'alert_name', 'notes', 'marked_at',
    ];
    const esc = (v) => {
      const s = v === null || v === undefined ? '' : String(v);
      if (/[,"\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
      return s;
    };
    const lines = [cols.join(',')];
    for (const r of rows) lines.push(cols.map(c => esc(r[c])).join(','));
    res.setHeader('content-type', 'text/csv; charset=utf-8');
    res.setHeader('content-disposition',
      `attachment; filename="csp-coverage-${new Date().toISOString().slice(0,10)}.csv"`);
    res.send(lines.join('\n') + '\n');
  } catch (err) { next(err); }
});

// ─── Webhook secret management ─ JWT-auth (operator) ───────────────────────
//
// The operator generates / rotates a per-user webhook secret here, then
// configures their SIEM (XSIAM, Splunk, …) to POST alert events to
// /coverage-webhook/alert with the secret in the X-CSP-Webhook-Token header.
// We never re-display a secret after creation — only the bcrypt hash is
// stored. Rotation invalidates the previous token.

function generateWebhookSecret() {
  return 'whk_' + crypto.randomBytes(28).toString('hex');
}

// GET — show whether a secret exists + when it was created/used.
coverageRouter.get('/webhook/secret', (req, res) => {
  const row = db.prepare(`
    SELECT label, created_at, last_used_at
    FROM coverage_webhook_secrets WHERE user_id = ?
  `).get(req.user.id);
  res.json({
    exists: !!row,
    label: row?.label || null,
    created_at: row?.created_at || null,
    last_used_at: row?.last_used_at || null,
    endpoint: '/coverage-webhook/alert',
  });
});

// POST — create or rotate the secret. Returns the plaintext ONCE.
coverageRouter.post('/webhook/secret', (req, res) => {
  const secret = generateWebhookSecret();
  const hash = bcrypt.hashSync(secret, 10);
  const label = (req.body?.label || '').toString().slice(0, 100) || null;

  // Replace any existing secret for this user — single secret per user
  // keeps verification cheap (one bcrypt compare per webhook hit).
  db.prepare('DELETE FROM coverage_webhook_secrets WHERE user_id = ?').run(req.user.id);
  db.prepare(`
    INSERT INTO coverage_webhook_secrets (user_id, secret_hash, label)
    VALUES (?, ?, ?)
  `).run(req.user.id, hash, label);

  audit(req.user.id, 'coverage_webhook_secret_rotate', { label }, req.ip);

  res.json({
    secret,             // shown ONCE — operator must copy now
    label,
    endpoint: '/coverage-webhook/alert',
    header: 'X-CSP-Webhook-Token',
    sample: {
      method: 'POST',
      url: '/coverage-webhook/alert',
      headers: {
        'content-type': 'application/json',
        'X-CSP-Webhook-Token': secret,
      },
      body: {
        technique_id: 'T1059.001',
        alert_name: 'Suspicious PowerShell download cradle',
        severity: 'high',
        source: 'xsiam',
        notes: 'Optional free-text. Will appear on the Coverage tab.',
      },
    },
  });
});

// DELETE — revoke the webhook secret (no replacement).
coverageRouter.delete('/webhook/secret', (req, res) => {
  const r = db.prepare(
    'DELETE FROM coverage_webhook_secrets WHERE user_id = ?'
  ).run(req.user.id);
  audit(req.user.id, 'coverage_webhook_secret_revoke', null, req.ip);
  res.json({ ok: true, deleted: r.changes });
});

// Webhook-event history (last 50) — for debugging SIEM integration.
coverageRouter.get('/webhook/events', (req, res) => {
  const rows = db.prepare(`
    SELECT technique_id, source, alert_name, severity, status, reason, ip, created_at
    FROM coverage_webhook_events
    WHERE user_id = ?
    ORDER BY datetime(created_at) DESC LIMIT 50
  `).all(req.user.id);
  res.json({ events: rows });
});

// ─── Webhook receiver ─ NO JWT, authenticated by X-CSP-Webhook-Token ───────
//
// Rate-limited per IP to absorb misconfigured SIEMs without melting the
// API. A real WAF in front of this should also cap body size.
const webhookLimiter = rateLimit({
  windowMs: 60_000,
  max: 120,                // 2/sec sustained
  standardHeaders: true,
  legacyHeaders: false,
});
coverageWebhookRouter.use(webhookLimiter);

function authenticateWebhook(token) {
  // Single-secret-per-user keeps this O(N users). For a real product we'd
  // index by a token prefix. CSP is a lab tool — N is small.
  const rows = db.prepare(
    'SELECT id, user_id, secret_hash FROM coverage_webhook_secrets'
  ).all();
  for (const r of rows) {
    try {
      if (bcrypt.compareSync(token, r.secret_hash)) return r;
    } catch { /* malformed hash — skip */ }
  }
  return null;
}

coverageWebhookRouter.post('/alert', (req, res) => {
  const token = req.headers['x-csp-webhook-token'];
  const body = req.body || {};
  const rawDump = JSON.stringify(body).slice(0, 4000);  // cap stored body

  const logEvent = (userId, status, reason, techniqueId, alertName, severity, source) => {
    db.prepare(`
      INSERT INTO coverage_webhook_events
        (user_id, technique_id, source, alert_name, severity, status, reason, raw_body, ip)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      userId ?? null,
      techniqueId ?? null,
      source ?? null,
      alertName ?? null,
      severity ?? null,
      status,
      reason ?? null,
      rawDump,
      req.ip ?? null,
    );
  };

  if (!token) {
    logEvent(null, 'rejected', 'missing token', body.technique_id,
             body.alert_name, body.severity, body.source);
    return res.status(401).json({ error: 'missing X-CSP-Webhook-Token header' });
  }

  const secretRow = authenticateWebhook(token);
  if (!secretRow) {
    logEvent(null, 'rejected', 'invalid token', body.technique_id,
             body.alert_name, body.severity, body.source);
    return res.status(401).json({ error: 'invalid webhook token' });
  }

  const userId = secretRow.user_id;
  const techniqueId = (body.technique_id || '').toString().trim();
  if (!techniqueId) {
    logEvent(userId, 'rejected', 'missing technique_id', null,
             body.alert_name, body.severity, body.source);
    return res.status(400).json({ error: 'technique_id required in body' });
  }

  // Update secret last-used timestamp (auth proven).
  db.prepare(
    "UPDATE coverage_webhook_secrets SET last_used_at = datetime('now') WHERE id = ?"
  ).run(secretRow.id);

  const detectionStatus = (body.detection_status || 'detected').toString();
  if (!['detected', 'not_detected', 'partial'].includes(detectionStatus)) {
    logEvent(userId, 'rejected', 'invalid detection_status', techniqueId,
             body.alert_name, body.severity, body.source);
    return res.status(400).json({
      error: "detection_status must be 'detected' | 'not_detected' | 'partial'",
    });
  }

  const edrProduct = (body.edr_product || body.source || 'webhook').toString().slice(0, 60);
  const alertName  = (body.alert_name || '').toString().slice(0, 200) || null;
  const notes      = (body.notes || '').toString().slice(0, 1000) || null;
  const sourceTag  = 'webhook:' + (body.source || 'unknown').toString().slice(0, 40);

  // Upsert into coverage_results — same semantics as PUT /coverage/:id.
  const existing = db.prepare(`
    SELECT id FROM coverage_results
    WHERE user_id = ? AND technique_id = ?
    ORDER BY datetime(updated_at) DESC LIMIT 1
  `).get(userId, techniqueId);

  if (existing) {
    db.prepare(`
      UPDATE coverage_results
      SET detection_status = ?, edr_product = ?, alert_name = ?, notes = ?,
          source = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(detectionStatus, edrProduct, alertName, notes, sourceTag, existing.id);
  } else {
    db.prepare(`
      INSERT INTO coverage_results
        (user_id, technique_id, detection_status, edr_product, alert_name, notes, source)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(userId, techniqueId, detectionStatus, edrProduct, alertName, notes, sourceTag);
  }

  logEvent(userId, 'accepted', null, techniqueId, alertName, body.severity, body.source);
  audit(userId, 'coverage_webhook_alert',
    { technique_id: techniqueId, detection_status: detectionStatus, source: body.source },
    req.ip);

  res.json({
    ok: true,
    technique_id: techniqueId,
    detection_status: detectionStatus,
    edr_product: edrProduct,
  });
});
