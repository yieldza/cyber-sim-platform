import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { v4 as uuid } from 'uuid';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { audit, db } from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';
import {
  consumeEnrollToken,
  generateAgentSecret,
  generateEnrollToken,
  hashAgentSecret,
  requireAgent,
} from '../services/agentAuth.js';
import { callWorker } from '../services/workerClient.js';
import { sweepDormantAgents, agentSweepConfig } from '../services/agentSweeper.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// Inside the API image agent/ is bundled at /app/agent ; in dev it lives
// alongside the api directory.
const AGENT_DIR = process.env.AGENT_DIR
  || (existsSync('/app/agent') ? '/app/agent' : join(__dirname, '../../../agent'));

const AGENT_FILES = {
  python:           { path: 'python/csp_agent.py',          filename: 'csp_agent.py',     mime: 'text/x-python' },
  powershell:       { path: 'powershell/csp-agent.ps1',     filename: 'csp-agent.ps1',    mime: 'application/x-powershell' },
  // Companion launcher to powershell — bypasses ExecutionPolicy so the
  // user never gets the "running scripts is disabled" prompt.
  'powershell-cmd': { path: 'powershell/csp-agent.cmd',     filename: 'csp-agent.cmd',    mime: 'application/x-bat' },
  csharp:           { path: 'csharp/CspAgent.cs',           filename: 'CspAgent.cs',      mime: 'text/x-csharp' },
};

export const operatorAgentsRouter = Router();   // /api/agents/*  (operator UI)
export const agentChannelRouter = Router();     // /agent-c2/*    (agent endpoints)

// ─── operator-side, JWT-auth ───────────────────────────────────
operatorAgentsRouter.use(requireAuth);

// ----- Agent source download (operator-side, JWT-auth) -----
// GET /api/agents/download/:lang  →  raw script bytes, with the right
// Content-Disposition so the browser saves it. Removes the manual "copy
// from repo" step in the previous UI.
operatorAgentsRouter.get('/download/:lang', (req, res) => {
  const meta = AGENT_FILES[req.params.lang];
  if (!meta) return res.status(404).json({ error: 'unknown agent language' });
  const fullPath = join(AGENT_DIR, meta.path);
  if (!existsSync(fullPath)) {
    return res.status(500).json({ error: 'agent source missing on server', path: fullPath });
  }
  let body = readFileSync(fullPath, 'utf8');

  // Inject a header note about chmod / ExecutionPolicy so users hit fewer
  // permission walls when running the freshly-downloaded script.
  if (req.params.lang === 'python') {
    // Insert chmod hint as a real comment between shebang and the docstring.
    const lines = body.split('\n');
    const insertAt = lines[0].startsWith('#!') ? 1 : 0;
    lines.splice(insertAt, 0,
      '# After saving on Linux/macOS:  chmod +x csp_agent.py',
      '# Or run without changing perms: python3 csp_agent.py --c2 ... --enroll-token ...',
      '');
    body = lines.join('\n');
  } else if (req.params.lang === 'powershell') {
    body =
      "# Easiest first run on Windows — download the .cmd launcher next to this\n" +
      "# .ps1 file and run that instead. The launcher auto-bypasses ExecutionPolicy:\n" +
      "#   csp-agent.cmd -C2 http://<csp-host>:8080 -EnrollToken ent_xxx\n" +
      "#\n" +
      "# Or, run this .ps1 directly with the bypass flag (no machine policy change):\n" +
      "#   PowerShell -ExecutionPolicy Bypass -File .\\csp-agent.ps1 -C2 ... -EnrollToken ...\n" +
      "# or, in an interactive session:  Set-ExecutionPolicy -Scope Process Bypass\n\n" +
      body;
  } else if (req.params.lang === 'csharp') {
    body =
      "// Build instructions:\n" +
      "//   dotnet new console -n CspAgent -o CspAgent\n" +
      "//   cp CspAgent.cs CspAgent/Program.cs\n" +
      "//   cd CspAgent && dotnet publish -c Release -r win-x64 \\\n" +
      "//     --self-contained false /p:PublishSingleFile=true\n" +
      "// Then run the produced .exe.\n\n" +
      body;
  }

  audit(req.user.id, 'agent_source_download',
    { lang: req.params.lang, filename: meta.filename }, req.ip);

  res.setHeader('Content-Type', meta.mime);
  res.setHeader('Content-Disposition', `attachment; filename="${meta.filename}"`);
  res.send(body);
});

operatorAgentsRouter.post('/enroll-token', (req, res) => {
  const { label } = req.body || {};
  const { token, expires_at } = generateEnrollToken(req.user.id, label);
  audit(req.user.id, 'agent_enroll_token', { label, expires_at }, req.ip);
  res.json({ token, expires_at });
});

// ─── Dormant-agent housekeeping ────────────────────────────────────────────
// Static segments MUST be declared before /:id catch-all (the route-ordering
// bug we fixed in milestone C). Keep these contiguous.

operatorAgentsRouter.get('/dormant-config', (_req, res) => {
  res.json({
    dormant_threshold_hours: agentSweepConfig.dormantHours,
    sweep_interval_minutes:  agentSweepConfig.sweepIntervalMinutes,
  });
});

operatorAgentsRouter.post('/sweep-dormant', (req, res) => {
  // Manual trigger — useful right after killing a batch of test endpoints
  // when the operator doesn't want to wait for the scheduled sweep.
  const hours = Math.max(1, parseInt(req.body?.hours, 10) || agentSweepConfig.dormantHours);
  const marked = sweepDormantAgents({ hours });
  // Filter to caller's own agents for the response so we don't leak
  // hostnames from other users' agents (the underlying sweep is global,
  // which is correct — anyone's stale agents should be flagged).
  const mine = marked.filter(m => m.user_id === req.user.id);
  audit(req.user.id, 'agent_sweep_manual',
    { hours, marked_total: marked.length, marked_mine: mine.length }, req.ip);
  res.json({
    threshold_hours: hours,
    marked_total: marked.length,
    marked: mine.map(m => ({ id: m.id, hostname: m.hostname, last_seen: m.last_seen })),
  });
});

// Hard-delete every dormant agent that belongs to the caller. Cascades
// to their tasks. Skipped agents (active/killed) are unaffected.
operatorAgentsRouter.post('/cleanup-dormant', (req, res) => {
  const rows = db.prepare(
    "SELECT id FROM agents WHERE user_id = ? AND status = 'dormant'"
  ).all(req.user.id);
  if (!rows.length) return res.json({ deleted: 0, agents: [] });

  const delTasks  = db.prepare('DELETE FROM agent_tasks WHERE agent_id = ?');
  const delAgent  = db.prepare('DELETE FROM agents WHERE id = ?');
  const tx = db.transaction((ids) => {
    for (const id of ids) { delTasks.run(id); delAgent.run(id); }
  });
  tx(rows.map(r => r.id));

  audit(req.user.id, 'agent_cleanup_dormant',
    { count: rows.length, ids: rows.map(r => r.id) }, req.ip);
  res.json({ deleted: rows.length, agents: rows.map(r => r.id) });
});

// Static segment must be declared BEFORE /:id catch-all
operatorAgentsRouter.get('/tasks/:taskId', (req, res) => {
  const row = db.prepare(`
    SELECT t.*
    FROM agent_tasks t JOIN agents a ON a.id = t.agent_id
    WHERE t.id = ? AND a.user_id = ?
  `).get(req.params.taskId, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row);
});

operatorAgentsRouter.get('/', (req, res) => {
  const rows = db.prepare(`
    SELECT id, hostname, platform, agent_version, internal_ip, external_ip,
           beacon_count, status, last_seen, created_at
    FROM agents
    WHERE user_id = ?
    ORDER BY datetime(created_at) DESC
  `).all(req.user.id);
  res.json({ agents: rows });
});

operatorAgentsRouter.get('/:id', (req, res) => {
  const a = db.prepare('SELECT * FROM agents WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  delete a.secret_hash;
  res.json(a);
});

operatorAgentsRouter.post('/:id/kill', (req, res) => {
  const r = db.prepare('UPDATE agents SET status = "killed" WHERE id = ? AND user_id = ?')
    .run(req.params.id, req.user.id);
  if (r.changes === 0) return res.status(404).json({ error: 'not found' });
  audit(req.user.id, 'agent_kill', { agent_id: req.params.id }, req.ip);
  res.json({ ok: true });
});

// DELETE — hard-remove an agent row. Cascades to its tasks. Use after
// the agent has confirmed shutdown (or for housekeeping of dormant rows).
operatorAgentsRouter.delete('/:id', (req, res) => {
  const own = db.prepare('SELECT id FROM agents WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!own) return res.status(404).json({ error: 'not found' });
  db.prepare('DELETE FROM agent_tasks WHERE agent_id = ?').run(req.params.id);
  db.prepare('DELETE FROM agents WHERE id = ?').run(req.params.id);
  audit(req.user.id, 'agent_delete', { agent_id: req.params.id }, req.ip);
  res.json({ ok: true });
});

operatorAgentsRouter.get('/:id/tasks', (req, res) => {
  const own = db.prepare('SELECT id FROM agents WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!own) return res.status(404).json({ error: 'not found' });
  const rows = db.prepare(`
    SELECT id, technique_id, test_name, executor, status, exit_code,
           duration_ms, sent_at, finished_at, created_at
    FROM agent_tasks
    WHERE agent_id = ?
    ORDER BY datetime(created_at) DESC
    LIMIT 100
  `).all(req.params.id);
  res.json({ tasks: rows });
});

operatorAgentsRouter.post('/:id/tasks', async (req, res, next) => {
  try {
    const { technique_id, test_name, timeout_sec } = req.body || {};
    if (!technique_id || !test_name) {
      return res.status(400).json({ error: 'technique_id and test_name required' });
    }
    const agent = db.prepare('SELECT * FROM agents WHERE id = ? AND user_id = ? AND status = "active"')
      .get(req.params.id, req.user.id);
    if (!agent) return res.status(404).json({ error: 'agent not found or killed' });

    // Pull catalog entry from worker — server is the source of truth for the command body.
    const catalog = await callWorker(`/techniques/${encodeURIComponent(technique_id)}`, null, { method: 'GET' });
    const test = (catalog.tests || []).find(t => t.name === test_name);
    if (!test) return res.status(404).json({ error: 'test not in catalog' });
    if (!test.platforms.includes(agent.platform)) {
      return res.status(400).json({
        error: `test platforms ${test.platforms.join(',')} do not match agent platform ${agent.platform}`,
      });
    }

    const id = uuid();
    db.prepare(`
      INSERT INTO agent_tasks
        (id, agent_id, created_by, technique_id, test_name, executor, command,
         cleanup, timeout_sec, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `).run(
      id, agent.id, req.user.id, technique_id, test_name,
      test.executor, test.command, test.cleanup ?? null,
      Math.max(1, Math.min(timeout_sec || 15, 60)),
    );
    audit(req.user.id, 'agent_task_queue',
      { agent_id: agent.id, task_id: id, technique_id, test_name }, req.ip);
    res.json({ task_id: id, agent_id: agent.id, status: 'pending' });
  } catch (err) { next(err); }
});

// ─── agent-side, no JWT ─ HTTP-polling C2 channel ──────────────
const agentLimiter = rateLimit({
  windowMs: 60_000,
  max: 600,           // tolerates a beacon every ~5s for an army of agents
  standardHeaders: true,
  legacyHeaders: false,
});
agentChannelRouter.use(agentLimiter);

// /register — consumes an enrollment token, returns agent_id + agent_secret
agentChannelRouter.post('/register', (req, res) => {
  const { enroll_token, hostname, platform, agent_version, internal_ip } = req.body || {};
  if (!enroll_token) return res.status(400).json({ error: 'enroll_token required' });
  if (!['linux', 'macos', 'windows'].includes(platform)) {
    return res.status(400).json({ error: 'platform must be linux|macos|windows' });
  }
  const id = 'agt_' + uuid().replace(/-/g, '').slice(0, 16);
  const tokenRow = consumeEnrollToken(enroll_token, id);
  if (!tokenRow) return res.status(401).json({ error: 'invalid or expired enroll_token' });

  const secret = generateAgentSecret();
  const externalIp = req.ip;
  db.prepare(`
    INSERT INTO agents
      (id, user_id, hostname, platform, agent_version,
       internal_ip, external_ip, secret_hash, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(
    id, tokenRow.user_id, hostname || null, platform,
    agent_version || null, internal_ip || null, externalIp,
    hashAgentSecret(secret),
  );
  audit(tokenRow.user_id, 'agent_register',
    { agent_id: id, hostname, platform }, externalIp);
  res.json({ agent_id: id, agent_secret: secret, beacon_interval_sec: 30 });
});

agentChannelRouter.post('/beacon', requireAgent, (req, res) => {
  // Always bump beacon_count + last_seen so operators can confirm the
  // agent process is still alive even up to its final shutdown beacon.
  db.prepare(`
    UPDATE agents
    SET last_seen = datetime('now'),
        beacon_count = beacon_count + 1
    WHERE id = ?
  `).run(req.agent.id);

  // If the operator killed this agent in the console, send a shutdown
  // signal on this beacon. Agent loop exits cleanly. No tasks issued.
  if (req.agent.status === 'killed') {
    audit(null, 'agent_shutdown_signal_sent',
      { agent_id: req.agent.id, reason: 'killed_by_operator' }, req.ip);
    return res.json({
      server_time: new Date().toISOString(),
      beacon_interval_sec: 30,
      shutdown: true,
      reason: 'killed_by_operator',
      tasks: [],
    });
  }

  // A dormant-sweeper-marked agent that beacons again is alive — flip
  // it back to active. Tasks then flow normally on this same beacon.
  if (req.agent.status === 'dormant') {
    db.prepare("UPDATE agents SET status = 'active' WHERE id = ?").run(req.agent.id);
    audit(null, 'agent_revived_from_dormant',
      { agent_id: req.agent.id }, req.ip);
  }

  // Pull pending tasks for active agents only.
  const tasks = db.prepare(`
    SELECT id, technique_id, test_name, executor, command, cleanup, timeout_sec
    FROM agent_tasks
    WHERE agent_id = ? AND status = 'pending'
    ORDER BY datetime(created_at) ASC
    LIMIT 5
  `).all(req.agent.id);

  if (tasks.length) {
    const stmt = db.prepare("UPDATE agent_tasks SET status = 'sent', sent_at = datetime('now') WHERE id = ?");
    for (const t of tasks) stmt.run(t.id);
  }

  res.json({
    server_time: new Date().toISOString(),
    beacon_interval_sec: 30,
    shutdown: false,
    tasks,
  });
});

agentChannelRouter.post('/result', requireAgent, (req, res) => {
  const { task_id, exit_code, duration_ms, stdout, stderr, truncated, status } = req.body || {};
  if (!task_id) return res.status(400).json({ error: 'task_id required' });

  const own = db.prepare('SELECT id FROM agent_tasks WHERE id = ? AND agent_id = ?')
    .get(task_id, req.agent.id);
  if (!own) return res.status(404).json({ error: 'task not found for this agent' });

  const finalStatus = ['done', 'error', 'timeout'].includes(status) ? status : 'done';
  const cap = 32 * 1024;
  const stdoutS = (stdout || '').slice(0, cap);
  const stderrS = (stderr || '').slice(0, cap);

  db.prepare(`
    UPDATE agent_tasks
    SET status = ?, exit_code = ?, duration_ms = ?,
        stdout = ?, stderr = ?, truncated = ?, finished_at = datetime('now')
    WHERE id = ?
  `).run(
    finalStatus,
    Number.isInteger(exit_code) ? exit_code : null,
    Number.isInteger(duration_ms) ? duration_ms : null,
    stdoutS,
    stderrS,
    truncated ? 1 : 0,
    task_id,
  );
  audit(null, 'agent_task_result',
    { agent_id: req.agent.id, task_id, status: finalStatus, exit_code }, req.ip);
  res.json({ ok: true });
});
