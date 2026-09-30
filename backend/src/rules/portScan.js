import { esClient, LOGS_INDEX } from '../es/client.js';

export const RULE_ID = 'R3';
export const RULE_NAME = 'Port scan';
export const SEVERITY = 'high';

const WINDOW = '30s';
const DISTINCT_PORT_THRESHOLD = 10;

/**
 * Same source IP hitting >= 10 distinct destination ports within 30 seconds,
 * sourced from Snort alerts. terms(source.ip) + cardinality(destination.port).
 */
export async function run() {
  const res = await esClient.search({
    index: LOGS_INDEX,
    size: 0,
    query: {
      bool: {
        filter: [
          { term: { 'log.source': 'snort' } },
          { range: { '@timestamp': { gte: `now-${WINDOW}` } } },
        ],
      },
    },
    aggs: {
      by_source_ip: {
        terms: { field: 'source.ip', size: 100 },
        aggs: {
          distinct_ports: { cardinality: { field: 'destination.port' } },
          affected_host: { terms: { field: 'destination.ip', size: 1 } },
          top_evidence: {
            top_hits: { size: 10, sort: [{ '@timestamp': 'desc' }] },
          },
        },
      },
    },
  });

  const buckets = res.aggregations?.by_source_ip?.buckets ?? [];

  return buildCandidatesFromBuckets(buckets);
}

export function buildCandidatesFromBuckets(buckets) {
  return buckets
    .filter((b) => b.distinct_ports.value >= DISTINCT_PORT_THRESHOLD)
    .map((bucket) => ({
      rule_id: RULE_ID,
      rule_name: RULE_NAME,
      severity: SEVERITY,
      source_ip: bucket.key,
      affected_host: bucket.affected_host.buckets[0]?.key ?? null,
      affected_user: null,
      evidence: bucket.top_evidence.hits.hits.map((h) => h._source),
      distinct_ports_hit: bucket.distinct_ports.value,
    }));
}
