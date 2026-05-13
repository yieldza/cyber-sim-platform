import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { audit, db } from '../db/index.js';
import { callWorker } from '../services/workerClient.js';
import {
  saveArtifact,
  getArtifact,
  listArtifacts,
  deleteArtifact,
  deleteArtifactsBulk,
} from '../services/artifactStore.js';

export const filesRouter = Router();

filesRouter.use(requireAuth);

filesRouter.get('/', (req, res) => {
  const { file_type, source_op, limit } = req.query;
  res.json({
    artifacts: listArtifacts(req.user.id, {
      fileType: file_type || undefined,
      sourceOp: source_op || undefined,
      limit: Math.min(parseInt(limit, 10) || 200, 500),
    }),
  });
});

// Distinct file_type / source_op values for the UI filter dropdowns.
filesRouter.get('/facets', (req, res) => {
  const file_types = db.prepare(
    'SELECT DISTINCT file_type FROM artifacts WHERE user_id = ? ORDER BY file_type'
  ).all(req.user.id).map(r => r.file_type);
  const source_ops = db.prepare(
    'SELECT DISTINCT source_op FROM artifacts WHERE user_id = ? ORDER BY source_op'
  ).all(req.user.id).map(r => r.source_op);
  res.json({ file_types, source_ops });
});

// Bulk delete — declared BEFORE /:id so the static path wins the route match.
// Body (or query): { file_type?, source_op?, all?: true }
filesRouter.delete('/', (req, res) => {
  const filters = { ...req.query, ...req.body };
  if (!filters.file_type && !filters.source_op && !(filters.all === true || filters.all === 'true')) {
    return res.status(400).json({
      error: 'specify file_type, source_op, or all=true',
    });
  }
  const result = deleteArtifactsBulk(req.user.id, {
    fileType: filters.file_type,
    sourceOp: filters.source_op,
  });
  audit(req.user.id, 'artifacts_bulk_delete', { ...filters, deleted: result.deleted }, req.ip);
  res.json(result);
});

filesRouter.delete('/:id', (req, res) => {
  const r = deleteArtifact(req.params.id, req.user.id);
  if (!r.deleted) return res.status(404).json({ error: 'not found' });
  audit(req.user.id, 'artifact_delete', { id: req.params.id }, req.ip);
  res.json(r);
});

filesRouter.post('/generate', async (req, res, next) => {
  try {
    const { file_type, note, target_size_kb } = req.body || {};
    if (!file_type) return res.status(400).json({ error: 'file_type required' });

    // Validate target_size_kb client-side before round-tripping to the worker.
    let tsk = null;
    if (target_size_kb !== undefined && target_size_kb !== null && target_size_kb !== '') {
      tsk = Number(target_size_kb);
      if (!Number.isInteger(tsk) || tsk < 1 || tsk > 20480) {
        return res.status(400).json({ error: 'target_size_kb must be integer 1..20480 (20 MB cap)' });
      }
    }

    const data = await callWorker('/generate', { file_type, note, target_size_kb: tsk });
    const saved = saveArtifact({
      userId: req.user.id,
      fileType: file_type,
      dataB64: data.data_b64,
      hashes: data.hashes,
      size: data.size,
      sourceOp: 'generate',
      metadata: {
        note: note || null,
        natural_size_kb: data.natural_size_kb,
        target_size_kb: tsk,
      },
    });
    audit(req.user.id, 'generate', {
      id: saved.id,
      file_type,
      sha256: data.hashes.sha256,
      target_size_kb: tsk,
    }, req.ip);
    res.json({
      id: saved.id,
      file_type,
      size: data.size,
      natural_size_kb: data.natural_size_kb,
      target_size_kb: tsk,
      hashes: data.hashes,
    });
  } catch (err) {
    next(err);
  }
});

// Mutate a file the operator just uploaded from local disk (not in library).
// The uploaded bytes arrive as base64; the API stores the result as a new
// artifact (no parent_id, since the source is external).
filesRouter.post('/mutate-upload', async (req, res, next) => {
  try {
    const {
      data_b64,
      filename,
      file_type_hint,
      operation,
      n,
      algo,
      target_length,
      target_prefix,
      max_iterations,
    } = req.body || {};
    if (!data_b64) return res.status(400).json({ error: 'data_b64 required' });
    if (!operation) return res.status(400).json({ error: 'operation required' });

    // Approx size check (base64 expands by 4/3); 10 MB binary cap aligns with worker.
    const approxBytes = Math.floor((data_b64.length * 3) / 4);
    if (approxBytes > 10 * 1024 * 1024) {
      return res.status(413).json({ error: 'file too large (10 MB max)' });
    }

    const result = await callWorker('/mutate', {
      data_b64,
      operation,
      n,
      algo,
      target_length,
      target_prefix,
      max_iterations,
    });

    // file_type_hint is best-effort metadata only — we don't validate it server-side.
    const safeType = (file_type_hint || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '');
    const saved = saveArtifact({
      userId: req.user.id,
      fileType: safeType || 'bin',
      dataB64: result.data_b64,
      hashes: result.after,
      size: result.size,
      sourceOp: 'mutate-upload',
      metadata: {
        operation,
        iterations: result.iterations,
        before: result.before,
        original_filename: filename || null,
      },
      filename: filename ? `mutated-${filename}` : undefined,
    });
    audit(req.user.id, 'mutate-upload', {
      id: saved.id,
      original_filename: filename || null,
      operation,
      sha256: result.after.sha256,
    }, req.ip);

    res.json({
      id: saved.id,
      operation,
      iterations: result.iterations,
      before: result.before,
      after: result.after,
      size: result.size,
    });
  } catch (err) {
    next(err);
  }
});

filesRouter.post('/:id/mutate', async (req, res, next) => {
  try {
    const parent = getArtifact(req.params.id, req.user.id);
    if (!parent) return res.status(404).json({ error: 'artifact not found' });

    const { operation, n, algo, target_length, target_prefix, max_iterations } = req.body || {};
    if (!operation) return res.status(400).json({ error: 'operation required' });

    const result = await callWorker('/mutate', {
      data_b64: parent.bytes.toString('base64'),
      operation,
      n,
      algo,
      target_length,
      target_prefix,
      max_iterations,
    });

    const saved = saveArtifact({
      userId: req.user.id,
      fileType: parent.row.file_type,
      dataB64: result.data_b64,
      hashes: result.after,
      size: result.size,
      sourceOp: 'mutate',
      parentId: parent.row.id,
      metadata: { operation, iterations: result.iterations, before: result.before },
    });
    audit(req.user.id, 'mutate', { id: saved.id, parent: parent.row.id, operation, sha256: result.after.sha256 }, req.ip);
    res.json({
      id: saved.id,
      operation,
      iterations: result.iterations,
      before: result.before,
      after: result.after,
      size: result.size,
    });
  } catch (err) {
    next(err);
  }
});

filesRouter.post('/convert', async (req, res, next) => {
  try {
    const { target, mode = 'rewrap', pdf_text } = req.body || {};
    if (!target) return res.status(400).json({ error: 'target required' });
    const data = await callWorker('/convert', { target, mode, pdf_text });
    const saved = saveArtifact({
      userId: req.user.id,
      fileType: target,
      dataB64: data.data_b64,
      hashes: data.hashes,
      size: data.size,
      sourceOp: 'convert',
      metadata: { mode, detected_as: data.detected_as },
    });
    audit(req.user.id, 'convert', { id: saved.id, target, mode, sha256: data.hashes.sha256 }, req.ip);
    res.json({
      id: saved.id,
      target,
      mode,
      detected_as: data.detected_as,
      size: data.size,
      hashes: data.hashes,
    });
  } catch (err) {
    next(err);
  }
});

filesRouter.get('/:id', (req, res) => {
  const a = getArtifact(req.params.id, req.user.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  res.json({
    id: a.row.id,
    file_type: a.row.file_type,
    filename: a.row.filename,
    size: a.row.size,
    md5: a.row.md5,
    sha1: a.row.sha1,
    sha256: a.row.sha256,
    source_op: a.row.source_op,
    parent_id: a.row.parent_id,
    metadata: a.row.metadata ? JSON.parse(a.row.metadata) : null,
    created_at: a.row.created_at,
  });
});

filesRouter.get('/:id/download', (req, res) => {
  const a = getArtifact(req.params.id, req.user.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  audit(req.user.id, 'download', { id: a.row.id, sha256: a.row.sha256 }, req.ip);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${a.row.filename}"`);
  res.send(a.bytes);
});
