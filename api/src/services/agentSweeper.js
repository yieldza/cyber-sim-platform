/**
 * Dormant-agent sweeper.
 *
 * Agents that go silent (process killed, host shut down, network cut)
 * still show up as "active" forever because there's no signal we ever
 * get from the dead agent. This sweeper marks them `dormant` after a
 * configurable threshold so the operator sees the real state.
 *
 * Reviving: if a dormant agent beacons in, the beacon handler flips it
 * back to `active` automatically (see routes/agents.js).
 *
 * Why a periodic timer instead of computing dormancy on read?
 * Computed-on-read would work, but persisting the status lets the
 * Coverage matrix + audit log + manual cleanup endpoint share one
 * source of truth without re-deriving timestamps everywhere.
 */
import { db, audit } from '../db/index.js';

// Read-once at module load so misconfigurations show up at startup.
const DORMANT_HOURS = parseInt(process.env.AGENT_DORMANT_HOURS || '24', 10);
const SWEEP_INTERVAL_MIN = parseInt(process.env.AGENT_SWEEP_INTERVAL_MIN || '60', 10);

if (!Number.isFinite(DORMANT_HOURS) || DORMANT_HOURS < 1) {
  throw new Error(`AGENT_DORMANT_HOURS must be a positive integer (got ${DORMANT_HOURS})`);
}
if (!Number.isFinite(SWEEP_INTERVAL_MIN) || SWEEP_INTERVAL_MIN < 1) {
  throw new Error(`AGENT_SWEEP_INTERVAL_MIN must be a positive integer (got ${SWEEP_INTERVAL_MIN})`);
}

export const agentSweepConfig = {
  dormantHours: DORMANT_HOURS,
  sweepIntervalMinutes: SWEEP_INTERVAL_MIN,
};

/**
 * Run one sweep. Returns the list of agents that were just marked dormant
 * so callers (manual endpoint, scheduler) can audit-log them.
 */
export function sweepDormantAgents({ hours = DORMANT_HOURS } = {}) {
  // SQLite datetime arithmetic: NULL last_seen also counts (never beaconed).
  const candidates = db.prepare(`
    SELECT id, user_id, hostname, last_seen
    FROM agents
    WHERE status = 'active'
      AND (last_seen IS NULL OR datetime(last_seen) < datetime('now', ?))
  `).all(`-${hours} hours`);

  if (!candidates.length) return [];

  const upd = db.prepare("UPDATE agents SET status = 'dormant' WHERE id = ?");
  const tx = db.transaction((rows) => { for (const r of rows) upd.run(r.id); });
  tx(candidates);

  // One audit entry summarising the sweep — per-agent rows would flood
  // the audit log on big deployments.
  audit(null, 'agent_dormant_sweep', {
    threshold_hours: hours,
    marked: candidates.map(c => c.id),
  }, null);

  return candidates;
}

let _timer = null;
export function startAgentSweepScheduler() {
  if (_timer) return;
  const periodMs = SWEEP_INTERVAL_MIN * 60_000;
  // Run once at boot so a long-down deployment converges immediately,
  // then on the regular schedule.
  try {
    const r = sweepDormantAgents();
    if (r.length) console.log(`[sweep] startup: marked ${r.length} agent(s) dormant`);
  } catch (e) {
    console.error(`[sweep] startup failed: ${e.message}`);
  }
  _timer = setInterval(() => {
    try {
      const r = sweepDormantAgents();
      if (r.length) console.log(`[sweep] periodic: marked ${r.length} agent(s) dormant`);
    } catch (e) {
      console.error(`[sweep] periodic failed: ${e.message}`);
    }
  }, periodMs);
  // Allow process exit if this is the only thing keeping node alive.
  if (typeof _timer.unref === 'function') _timer.unref();
}

export function stopAgentSweepScheduler() {
  if (_timer) {
    clearInterval(_timer);
    _timer = null;
  }
}
