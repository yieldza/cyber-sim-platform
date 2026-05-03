import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

import { authRouter } from './routes/auth.js';
import { filesRouter } from './routes/files.js';
import { techniquesRouter, runsRouter } from './routes/techniques.js';
import { operatorAgentsRouter, agentChannelRouter } from './routes/agents.js';
import { workerHealth } from './services/workerClient.js';
import './db/index.js'; // ensure schema bootstrap

const app = express();
const PORT = parseInt(process.env.PORT || '8080', 10);

app.use(cors());
app.use(express.json({ limit: '12mb' }));
app.use(morgan('combined'));

app.use(rateLimit({
  windowMs: 60_000,
  max: 240,
  standardHeaders: true,
  legacyHeaders: false,
}));

app.get('/healthz', async (_req, res) => {
  let workerOk = false;
  try {
    const h = await workerHealth();
    workerOk = !!h.ok;
  } catch {}
  res.json({ ok: true, worker: workerOk });
});

app.get('/', (_req, res) => {
  res.json({
    name: 'cyber-sim-platform',
    version: '0.1.0',
    safety: 'EICAR-only test payloads. Authorized blue-team detection testing.',
    docs: '/api/* routes; see README.md',
  });
});

app.use('/api/auth', authRouter);
app.use('/api/files', filesRouter);
app.use('/api/techniques', techniquesRouter);
app.use('/api/runs', runsRouter);
app.use('/api/agents', operatorAgentsRouter);
app.use('/agent-c2', agentChannelRouter);

// Centralized error handler
app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  console.error(`[err ${status}] ${err.message}`);
  res.status(status).json({ error: err.message });
});

app.listen(PORT, () => {
  console.log(`[api] listening on :${PORT}`);
});
