import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import 'dotenv/config';

import { pingElasticsearch } from './es/client.js';
import { startRuleEngine, runAllRules } from './rules/engine.js';
import { startEnrichmentPoller } from './enrichment/poller.js';

import logsRouter from './routes/logs.js';
import alertsRouter from './routes/alerts.js';
import statsRouter from './routes/stats.js';
import uploadsRouter from './routes/uploads.js';
import { MAX_UPLOAD_SIZE_MB } from './uploads/service.js';

const PORT = process.env.PORT || 4000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';

const app = express();
app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json({ limit: `${Math.max(2, MAX_UPLOAD_SIZE_MB * 2)}mb` }));

app.get('/api/health', async (req, res) => {
  const esOk = await pingElasticsearch();
  res.json({ status: esOk ? 'ok' : 'degraded', elasticsearch: esOk });
});

app.use('/api/logs', logsRouter);
app.use('/api/alerts', alertsRouter);
app.use('/api/stats', statsRouter);
app.use('/api/uploads', uploadsRouter);

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: FRONTEND_ORIGIN },
});
app.set('io', io);

io.on('connection', (socket) => {
  console.log(`[ws] client connected: ${socket.id}`);
  socket.on('disconnect', () => console.log(`[ws] client disconnected: ${socket.id}`));
});

httpServer.listen(PORT, async () => {
  console.log(`[server] CyberEye SIEM backend listening on :${PORT}`);

  const esOk = await pingElasticsearch();
  if (!esOk) {
    console.warn(
      '[server] Elasticsearch not reachable yet. Run `docker compose up -d` and `npm run setup` in backend/.'
    );
  }

  startRuleEngine(io);
  startEnrichmentPoller();

  // Run one rule engine pass immediately on boot rather than waiting for the
  // first cron tick, so a freshly-started demo shows alerts sooner.
  runAllRules(io).catch((err) => console.error('[rules] initial run failed:', err));
});
