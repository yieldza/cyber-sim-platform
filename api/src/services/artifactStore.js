import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
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

export function listArtifacts(userId, limit = 50) {
  return db
    .prepare(`
      SELECT id, file_type, filename, size, sha256, source_op, parent_id, created_at
      FROM artifacts
      WHERE user_id = ?
      ORDER BY datetime(created_at) DESC
      LIMIT ?
    `)
    .all(userId, limit);
}
