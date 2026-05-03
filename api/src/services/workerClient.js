const WORKER_URL = process.env.WORKER_URL || 'http://worker:8001';
const WORKER_API_KEY = process.env.WORKER_API_KEY || '';

export async function callWorker(path, body, { method = 'POST' } = {}) {
  const res = await fetch(`${WORKER_URL}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      'x-api-key': WORKER_API_KEY,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`worker ${path} ${res.status}: ${text}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export async function workerHealth() {
  return callWorker('/healthz', null, { method: 'GET' });
}
