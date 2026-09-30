import { pingElasticsearch } from './client.js';
import { ensureIndices } from './indices.js';
import { registerNormalizerPipelines } from '../ingest/normalizer.js';

// Run with `npm run setup` (from backend/) after Elasticsearch is up.
// Creates the siem-logs / siem-alerts indices and registers the ingest
// pipelines that Winlogbeat/Filebeat normalize events through.
async function main() {
  const alive = await pingElasticsearch();
  if (!alive) {
    console.error('[setup] Could not reach Elasticsearch. Is docker-compose up?');
    process.exit(1);
  }

  await ensureIndices();
  await registerNormalizerPipelines();

  console.log('[setup] Done. Indices and ingest pipelines are ready.');
  process.exit(0);
}

main().catch((err) => {
  console.error('[setup] failed:', err);
  process.exit(1);
});
