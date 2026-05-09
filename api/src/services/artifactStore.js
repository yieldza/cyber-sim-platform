import { mkdirSync, writeFileSync, readFileSync, existsSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { v4 as uuid } from 'uuid';
import { db } from '../db/index.js';

const STORE_ROOT = process.env.ARTIFACT_DIR || join(process.cwd(), 'data', 'artifacts');
mkdirSync(STORE_ROOT, { recursive: true });

const FILE_TYPE_EXT = {
  eicar: 'txt',
  com: 'com',
  pe: 'exe',
  pdf: 'pdf',
  apk: 'apk',
  docx: 'docx',
  zip: 'zip',
  // Behavioral droppers — text scripts, served with the matching extension
  // so the operator's host honours the right interpreter / shebang.
  'dropper-ps1': 'ps1',
  'dropper-sh': 'sh',
  'dropper-py': 'py',
  // ATT&CK script-host carriers (v0.4.0)
  'hta': 'hta',                    // T1218.005
  'vbs': 'vbs',                    // T1059.005
  'js': 'js',                      // T1059.007
  'html-smuggle': 'html',          // T1027.006
};

export function saveArtifact({
  userId,
  fileType,
  dataB64,
  hashes,
  size,
  sourceOp,
  parentId,
  metadata,
  filename,
}) {
  const id = uuid();
  const ext = FILE_TYPE_EXT[fileType] || 'bin';
  const safeName = filename || `${id}.${ext}`;
  const userDir = join(STORE_ROOT, String(userId));
  mkdirSync(userDir, { recursive: true });
  const storagePath = join(userDir, `${id}-${safeName}`);
  writeFileSync(storagePath, Buffer.from(dataB64, 'base64'));

  db.prepare(`
    INSERT INTO artifacts
      (id, user_id, file_type, filename, size, md5, sha1, sha256,
       storage_path, source_op, parent_id, metadata)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    userId,
    fileType,
    safeName,
    size,
    hashes.md5,
    hashes.sha1,
    hashes.sha256,
    storagePath,
    sourceOp,
    parentId ?? null,
    metadata ? JSON.stringify(metadata) : null,
  );

  return { id, filename: safeName, storage_path: storagePath };
}

export function getArtifact(id, userId) {
  const row = db.prepare('SELECT * FROM artifacts WHERE id = ? AND user_id = ?').get(id, userId);
  if (!row) return null;
  if (!existsSync(row.storage_path)) return null;
  return { row, bytes: readFileSync(row.storage_path) };
}

export function listArtifacts(userId, { limit = 200, fileType, sourceOp } = {}) {
  const where = ['user_id = ?'];
  const args = [userId];
  if (fileType) { where.push('file_type = ?'); args.push(fileType); }
  if (sourceOp) { where.push('source_op = ?'); args.push(sourceOp); }
  args.push(limit);
  return db
    .prepare(`
      SELECT id, file_type, filename, size, sha256, source_op, parent_id, created_at
      FROM artifacts
      WHERE ${where.join(' AND ')}
      ORDER BY datetime(created_at) DESC
      LIMIT ?
    `)
    .all(...args);
}

/** Delete one artifact (storage file + DB row) belonging to the caller. */
export function deleteArtifact(id, userId) {
  const row = db.prepare('SELECT id, storage_path FROM artifacts WHERE id = ? AND user_id = ?')
    .get(id, userId);
  if (!row) return { deleted: 0 };
  // Null out parent_id on children so we don't violate the FK on delete.
  db.prepare('UPDATE artifacts SET parent_id = NULL WHERE parent_id = ?').run(id);
  db.prepare('DELETE FROM artifacts WHERE id = ?').run(id);
  if (row.storage_path && existsSync(row.storage_path)) {
    try { unlinkSync(row.storage_path); } catch { /* best-effort */ }
  }
  return { deleted: 1, sha256_prefix: null };
}

/** Bulk delete with optional filter. Returns count of rows removed. */
export function deleteArtifactsBulk(userId, { fileType, sourceOp } = {}) {
  const where = ['user_id = ?'];
  const args = [userId];
  if (fileType) { where.push('file_type = ?'); args.push(fileType); }
  if (sourceOp) { where.push('source_op = ?'); args.push(sourceOp); }

  const rows = db.prepare(
    `SELECT id, storage_path FROM artifacts WHERE ${where.join(' AND ')}`
  ).all(...args);

  if (rows.length === 0) return { deleted: 0 };

  const ids = rows.map(r => r.id);
  const placeholders = ids.map(() => '?').join(',');
  // Detach any external children whose parent is in the delete set.
  db.prepare(`UPDATE artifacts SET parent_id = NULL WHERE parent_id IN (${placeholders})`)
    .run(...ids);
  db.prepare(`DELETE FROM artifacts WHERE id IN (${placeholders})`).run(...ids);

  for (const r of rows) {
    if (r.storage_path && existsSync(r.storage_path)) {
      try { unlinkSync(r.storage_path); } catch { /* best-effort */ }
    }
  }
  return { deleted: rows.length };
}
