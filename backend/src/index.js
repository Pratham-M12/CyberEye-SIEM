import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import 'dotenv/config';

import { pingElasticsearch } from './es/client.js';
import { ensureIndices } from './es/indices.js';
import { startRuleEngine, runAllRules } from './rules/engine.js';
import { startEnrichmentPoller } from './enrichment/poller.js';
import { apiLimiter } from './middleware/rateLimiter.js';
import { verifyToken } from './auth/jwt.js';
import { seedAdmin } from './scripts/seedAdmin.js';

import authRouter from './routes/auth.js';
import usersRouter from './routes/users.js';
import logsRouter from './routes/logs.js';
import alertsRouter from './routes/alerts.js';
import statsRouter from './routes/stats.js';
import uploadsRouter from './routes/uploads.js';
import { MAX_UPLOAD_SIZE_MB } from './uploads/service.js';

const PORT = process.env.PORT || 4000;
const allowedOrigins = (process.env.FRONTEND_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const app = express();

// Disable Express fingerprinting header
app.disable('x-powered-by');

// Standard security headers without extra third-party dependencies
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '0');
  next();
});

// Hardened CORS configuration supporting specific origins or LAN IPs
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. server-to-server, curl, health probes)
      if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
        return callback(null, true);
      }
      return callback(new Error('CORS origin not allowed'));
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// Apply JSON body parser with strict size limit
app.use(express.json({ limit: `${Math.max(2, MAX_UPLOAD_SIZE_MB * 2)}mb` }));

// Health check endpoint (safe: only returns boolean/status, no credentials or env vars)
app.get(['/health', '/api/health'], async (req, res) => {
  const esOk = await pingElasticsearch();
  res.json({ status: esOk ? 'ok' : 'degraded', elasticsearch: esOk });
});

// Apply conservative rate limiting to all API routes
app.use('/api', apiLimiter);

// Mount feature routers
app.use('/api/auth', authRouter);
app.use('/api/users', usersRouter);
app.use('/api/logs', logsRouter);
app.use('/api/alerts', alertsRouter);
app.use('/api/stats', statsRouter);
app.use('/api/uploads', uploadsRouter);

// Convenience aliases for summary, timeline, and top-attackers
app.use('/api/summary', (req, res, next) => {
  req.url = '/summary' + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
  statsRouter(req, res, next);
});
app.use('/api/timeline', (req, res, next) => {
  req.url = '/timeline' + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
  statsRouter(req, res, next);
});
app.use('/api/top-attackers', (req, res, next) => {
  req.url = '/top-attackers' + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
  alertsRouter(req, res, next);
});

// 404 handler for undefined API routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handling middleware (prevents stack traces and raw error disclosure)
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Malformed JSON payload' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload exceeds maximum allowed size' });
  }
  if (err.message === 'CORS origin not allowed') {
    return res.status(403).json({ error: 'CORS request blocked from this origin' });
  }

  console.error('[server] unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: allowedOrigins.length === 1 ? allowedOrigins[0] : allowedOrigins },
});
app.set('io', io);

// Socket.IO authentication middleware: verifies JWT from handshake auth token or Authorization header
io.use((socket, next) => {
  try {
    const token =
      socket.handshake.auth?.token ||
      (socket.handshake.headers?.authorization && socket.handshake.headers.authorization.startsWith('Bearer ')
        ? socket.handshake.headers.authorization.slice(7).trim()
        : null);

    if (!token) {
      return next(new Error('Authentication required'));
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return next(new Error('Invalid or expired token'));
    }

    socket.user = decoded;
    next();
  } catch (err) {
    return next(new Error('Authentication failed'));
  }
});

io.on('connection', (socket) => {
  console.log(`[ws] client connected: ${socket.id} (user: ${socket.user?.username || 'unknown'}, role: ${socket.user?.role || 'none'})`);
  socket.on('disconnect', () => console.log(`[ws] client disconnected: ${socket.id}`));
});

httpServer.listen(PORT, async () => {
  console.log(`[server] CyberEye SIEM backend listening on :${PORT}`);

  const esOk = await pingElasticsearch();
  if (!esOk) {
    console.warn(
      '[server] Elasticsearch not reachable yet. Run `docker compose up -d` and `npm run setup` in backend/.'
    );
  } else {
    try {
      await ensureIndices();
      await seedAdmin();
    } catch (err) {
      console.warn('[server] Setup warning:', err.message);
    }
  }

  startRuleEngine(io);
  startEnrichmentPoller();

  // Run one rule engine pass immediately on boot rather than waiting for the
  // first cron tick, so a freshly-started demo shows alerts sooner.
  runAllRules(io).catch((err) => console.error('[rules] initial run failed:', err.message));
});

