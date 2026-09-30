// backend/src/routes/logs.js
import { Router } from 'express';
import { esClient, LOGS_INDEX } from '../es/client.js';

const router = Router();

// GET /api/logs?source=windows&event_type=auth_failure&severity=high
//     &from=2026-07-01T00:00:00Z&to=2026-07-02T00:00:00Z&page=1&pageSize=50&q=free+text
router.get('/', async (req, res) => {
  try {
    const {
      source,
      event_type: eventType,
      severity,
      source_ip: sourceIp,
      from,
      to,
      page = '1',
      pageSize = '50',
      q,
    } = req.query;

    const filter = [];
    if (source) filter.push({ term: { 'log.source': source } });
    if (eventType) filter.push({ term: { 'event.type': eventType } });
    if (severity) filter.push({ term: { 'event.severity': severity } });
    if (sourceIp) filter.push({ term: { 'source.ip': sourceIp } });
    if (from || to) {
      filter.push({
        range: {
          '@timestamp': {
            ...(from ? { gte: from } : {}),
            ...(to ? { lte: to } : {}),
          },
        },
      });
    }

    const must = q ? [{ query_string: { query: q, default_field: 'raw_message' } }] : [];

    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const size = Math.min(200, parseInt(pageSize, 10) || 50);

    const result = await esClient.search({
      index: LOGS_INDEX,
      from: (pageNum - 1) * size,
      size,
      sort: [{ '@timestamp': 'desc' }],
      query: { bool: { filter, must } },
    });

    res.json({
      total: result.hits.total.value,
      page: pageNum,
      pageSize: size,
      logs: result.hits.hits.map((h) => ({ id: h._id, ...h._source })),
    });
  } catch (err) {
    console.error('[api] GET /logs failed:', err);
    res.status(500).json({ error: 'Failed to query logs' });
  }
});

export default router;
