import { Router } from 'express';
import { esClient, LOGS_INDEX, ALERTS_INDEX } from '../es/client.js';
import { isValidTimeWindow, isValidInterval } from '../middleware/validate.js';
import { authenticate } from '../middleware/auth.js';

const router = Router();

// Protect all /api/stats routes with authentication
router.use(authenticate);

// GET /api/stats/timeline?window=24h&interval=1h
// Event volume by log source, bucketed over time — feeds the Recharts area chart.
router.get('/timeline', async (req, res) => {
  try {
    const { window = '24h', interval = '1h' } = req.query;

    if (!isValidTimeWindow(window)) {
      return res.status(400).json({ error: 'Invalid window parameter. Allowed format: 15m, 1h, 24h, 7d' });
    }

    if (!isValidInterval(interval)) {
      return res.status(400).json({ error: 'Invalid interval parameter. Allowed format: 1m, 5m, 1h, 1d' });
    }

    const result = await esClient.search({
      index: LOGS_INDEX,
      size: 0,
      query: {
        bool: { filter: [{ range: { '@timestamp': { gte: `now-${window}` } } }] },
      },
      aggs: {
        over_time: {
          date_histogram: { field: '@timestamp', fixed_interval: interval },
          aggs: {
            by_source: { terms: { field: 'log.source', size: 10 } },
          },
        },
      },
    });

    const buckets = result.aggregations?.over_time?.buckets ?? [];
    const timeline = buckets.map((bucket) => {
      const point = { timestamp: bucket.key_as_string };
      for (const sourceBucket of bucket.by_source.buckets) {
        point[sourceBucket.key] = sourceBucket.doc_count;
      }
      return point;
    });

    res.json({ timeline });
  } catch (err) {
    console.error('[api] GET /stats/timeline failed:', err.message);
    res.status(500).json({ error: 'Failed to compute timeline' });
  }
});

// GET /api/stats/summary — small counters for the dashboard header.
router.get('/summary', async (req, res) => {
  try {
    const [logsCount, openAlerts, criticalAlerts] = await Promise.all([
      esClient.count({ index: LOGS_INDEX, query: { range: { '@timestamp': { gte: 'now-24h' } } } }),
      esClient.count({ index: ALERTS_INDEX, query: { term: { status: 'open' } } }),
      esClient.count({
        index: ALERTS_INDEX,
        query: { bool: { filter: [{ term: { severity: 'critical' } }, { term: { status: 'open' } }] } },
      }),
    ]);

    res.json({
      events_last_24h: logsCount.count,
      open_alerts: openAlerts.count,
      open_critical_alerts: criticalAlerts.count,
    });
  } catch (err) {
    console.error('[api] GET /stats/summary failed:', err.message);
    res.status(500).json({ error: 'Failed to compute summary' });
  }
});

export default router;
