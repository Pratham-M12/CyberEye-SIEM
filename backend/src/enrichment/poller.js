import cron from 'node-cron';
import 'dotenv/config';
import { esClient, LOGS_INDEX } from '../es/client.js';
import { enrichIngestedEvent } from './abuseipdb.js';

// Beats write straight to Elasticsearch, so there's no Node.js ingest
// endpoint to hook AbuseIPDB into synchronously. Instead this poller finds
// recently-indexed events that are missing threat.* fields and enriches
// them in small batches, on a timer independent of the 30s rule engine.
const POLL_CRON = '*/60 * * * * *'; // every 60s
const BATCH_SIZE = 25;

export function startEnrichmentPoller() {
  cron.schedule(POLL_CRON, () => {
    pollAndEnrich().catch((err) => console.error('[enrichment] poll failed:', err.message));
  });
}

async function pollAndEnrich() {
  const res = await esClient.search({
    index: LOGS_INDEX,
    size: BATCH_SIZE,
    query: {
      bool: {
        filter: [{ range: { '@timestamp': { gte: 'now-5m' } } }],
        must_not: [{ exists: { field: 'threat.score' } }],
      },
    },
    _source: ['source.ip'],
  });

  const hits = res.hits.hits;
  if (hits.length === 0) return;

  for (const hit of hits) {
    const sourceIp = hit._source?.['source.ip'];
    if (!sourceIp) continue;
    await enrichIngestedEvent(hit._id, sourceIp);
  }
}
