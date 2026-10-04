// backend/src/routes/alerts.js
import { Router } from 'express';
import { esClient, ALERTS_INDEX } from '../es/client.js';
import { summarizeAlert } from '../llm/summarizer.js';
import { generateInvestigation } from '../services/investigationService.js';
import {
  validatePagination,
  isValidId,
  isValidSeverity,
  isValidStatus,
  isValidTimeWindow,
} from '../middleware/validate.js';
import { aiLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// GET /api/alerts?severity=critical&status=open&page=1&pageSize=50
router.get('/', async (req, res) => {
  try {
    const { severity, status, page = '1', pageSize = '50' } = req.query;

    const { pageNum, size, error: pagError } = validatePagination(page, pageSize);
    if (pagError) {
      return res.status(400).json({ error: pagError });
    }

    if (severity && !isValidSeverity(severity)) {
      return res.status(400).json({ error: 'Invalid severity parameter' });
    }

    if (status && !isValidStatus(status)) {
      return res.status(400).json({ error: 'Invalid status parameter' });
    }

    const filter = [];
    if (severity) filter.push({ term: { severity } });
    if (status) filter.push({ term: { status } });

    const result = await esClient.search({
      index: ALERTS_INDEX,
      from: (pageNum - 1) * size,
      size,
      sort: [{ '@timestamp': 'desc' }],
      query: { bool: { filter } },
    });

    res.json({
      total: result.hits.total.value,
      page: pageNum,
      pageSize: size,
      alerts: result.hits.hits.map((h) => ({ id: h._id, ...h._source })),
    });
  } catch (err) {
    console.error('[api] GET /alerts failed:', err.message);
    res.status(500).json({ error: 'Failed to query alerts' });
  }
});

// GET /api/alerts/top-attackers?window=24h&limit=10
router.get('/top-attackers', async (req, res) => {
  try {
    const { window = '24h', limit = '10' } = req.query;

    if (!isValidTimeWindow(window)) {
      return res.status(400).json({ error: 'Invalid window parameter. Allowed format: 15m, 1h, 24h, 7d' });
    }

    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 10));

    const result = await esClient.search({
      index: ALERTS_INDEX,
      size: 0,
      query: {
        bool: { filter: [{ range: { '@timestamp': { gte: `now-${window}` } } }] },
      },
      aggs: {
        top_ips: {
          terms: { field: 'source_ip', size: limitNum },
        },
      },
    });

    const buckets = result.aggregations?.top_ips?.buckets ?? [];
    res.json({
      attackers: buckets.map((b) => ({ source_ip: b.key, alert_count: b.doc_count })),
    });
  } catch (err) {
    console.error('[api] GET /alerts/top-attackers failed:', err.message);
    res.status(500).json({ error: 'Failed to compute top attackers' });
  }
});

// GET /api/alerts/:id
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      return res.status(400).json({ error: 'Invalid alert ID' });
    }

    const doc = await esClient.get({ index: ALERTS_INDEX, id });
    res.json({ id: doc._id, ...doc._source });
  } catch (err) {
    if (err.meta?.statusCode === 404) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    console.error('[api] GET /alerts/:id failed:', err.message);
    res.status(500).json({ error: 'Failed to fetch alert' });
  }
});

// POST /api/alerts/:id/summary — on-demand LLM analyst summary
router.post('/:id/summary', aiLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      return res.status(400).json({ error: 'Invalid alert ID' });
    }

    const doc = await esClient.get({ index: ALERTS_INDEX, id });
    const alert = { id: doc._id, ...doc._source };

    if (alert.llm_summary) {
      return res.json({ summary: alert.llm_summary, generated: true, cached: true });
    }

    const { summary, generated } = await summarizeAlert(alert);

    if (generated) {
      await esClient.update({
        index: ALERTS_INDEX,
        id: alert.id,
        doc: { llm_summary: summary },
      });
    }

    res.json({ summary, generated, cached: false });
  } catch (err) {
    if (err.meta?.statusCode === 404) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    console.error('[api] POST /alerts/:id/summary failed:', err.message);
    res.status(500).json({ error: 'Failed to generate summary' });
  }
});

// POST /api/alerts/:id/investigate
router.post('/:id/investigate', aiLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      return res.status(400).json({ error: 'Invalid alert ID' });
    }

    const result = await generateInvestigation(id);
    res.json(result);
  } catch (err) {
    if (err.meta?.statusCode === 404) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    console.error('[api] POST /alerts/:id/investigate failed:', err.message);
    res.status(500).json({ error: 'Failed to generate investigation' });
  }
});

// PATCH /api/alerts/:id/status — { status: "acknowledged" | "closed" | "open" }
router.patch('/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      return res.status(400).json({ error: 'Invalid alert ID' });
    }

    const { status } = req.body || {};
    if (!['open', 'acknowledged', 'closed'].includes(status)) {
      return res.status(400).json({
        error: 'Invalid status',
      });
    }

    const existing = await esClient.get({
      index: ALERTS_INDEX,
      id,
    });

    const source = existing._source;
    const now = new Date().toISOString();

    const history = Array.isArray(source.history)
      ? [...source.history]
      : [
          {
            action: 'created',
            status: source.status ?? 'open',
            by: source.updatedBy ?? 'system',
            timestamp:
              source.createdAt ??
              source['@timestamp'] ??
              now,
          },
        ];

    history.push({
      action: status,
      status,
      by: 'local-user',
      timestamp: now,
    });

    await esClient.update({
      index: ALERTS_INDEX,
      id,
      doc: {
        status,
        updatedAt: now,
        updatedBy: 'local-user',
        history,
      },
    });

    res.json({
      id,
      status,
      updatedAt: now,
    });
  } catch (err) {
    if (err.meta?.statusCode === 404) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    console.error('[api] PATCH /alerts/:id/status failed:', err.message);
    res.status(500).json({
      error: 'Failed to update alert status',
    });
  }
});

export default router;
