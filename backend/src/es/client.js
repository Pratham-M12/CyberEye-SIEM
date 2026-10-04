import { Client } from '@elastic/elasticsearch';
import 'dotenv/config';

// Single shared Elasticsearch client instance.
// TLS/auth are intentionally disabled here for local dev, per project constraints.
// Enable `auth` / `tls` options before deploying anywhere outside localhost.
export const esClient = new Client({
  node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
});

export const LOGS_INDEX = process.env.ES_LOGS_INDEX || 'siem-logs';
export const ALERTS_INDEX = process.env.ES_ALERTS_INDEX || 'siem-alerts';
export const USERS_INDEX = process.env.ES_USERS_INDEX || 'siem-users';

export async function pingElasticsearch() {
  try {
    const alive = await esClient.ping();
    return Boolean(alive);
  } catch (err) {
    console.error('[elasticsearch] ping failed:', err.message);
    return false;
  }
}
