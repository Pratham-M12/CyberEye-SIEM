import { Router } from 'express';
import { esClient, LOGS_INDEX } from '../es/client.js';
import {
  validatePagination,
  isValidIp,
  isValidSeverity,
  isValidDateString,
  sanitizeSearchQuery,
} from '../middleware/validate.js';

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

    const { pageNum, size, error: pagError } = validatePagination(page, pageSize);
    if (pagError) {
      return res.status(400).json({ error: pagError });
    }

    if (severity && !isValidSeverity(severity)) {
      return res.status(400).json({ error: 'Invalid severity parameter' });
    }

    if (sourceIp && !isValidIp(sourceIp)) {
      return res.status(400).json({ error: 'Invalid source_ip parameter' });
    }

    if (from && !isValidDateString(from)) {
      return res.status(400).json({ error: 'Invalid "from" timestamp format' });
    }

    if (to && !isValidDateString(to)) {
      return res.status(400).json({ error: 'Invalid "to" timestamp format' });
    }

    const filter = [];
    if (source) {
      const cleanSource = String(source).trim().slice(0, 100);
      filter.push({ term: { 'log.source': cleanSource } });
    }
    if (eventType) {
      const cleanEventType = String(eventType).trim().slice(0, 100);
      filter.push({ term: { 'event.type': cleanEventType } });
    }
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

    const sanitizedQ = sanitizeSearchQuery(q);
    const must = sanitizedQ
      ? [{ simple_query_string: { query: sanitizedQ, fields: ['raw_message'] } }]
      : [];

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
    console.error('[api] GET /logs failed:', err.message);
    res.status(500).json({ error: 'Failed to query logs' });
  }
});

export default router;
