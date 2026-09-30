import { esClient, LOGS_INDEX } from '../es/client.js';
import { SQLI_XSS_REGEX } from '../ingest/normalizer.js';

export const RULE_ID = 'R4';
export const RULE_NAME = 'Web attack (SQLi/XSS)';
export const SEVERITY = 'medium';

const WINDOW = '1m';
const ES_URI_REGEX = '.*' + SQLI_XSS_REGEX.replace('(?i)', '').replace(/</g, '\\<') + '.*';

/**
 * Apache/Nginx request URI matches a SQLi or XSS pattern. The ingest
 * pipeline already tags these as event.type = "web_attack"; this rule
 * re-confirms with a regex query directly against http.uri (defense in
 * depth, and useful if the pipeline tag was ever bypassed) and groups
 * matches by source IP.
 */
export async function run() {
  const res = await esClient.search({
    index: LOGS_INDEX,
    size: 0,
    query: {
      bool: {
        filter: [
          { terms: { 'log.source': ['nginx', 'apache'] } },
          { range: { '@timestamp': { gte: `now-${WINDOW}` } } },
        ],
        should: [
          { term: { 'event.type': 'web_attack' } },
          {
            regexp: {
              'http.uri': {
                value: ES_URI_REGEX,
                case_insensitive: true,
              },
            },
          },
        ],
        minimum_should_match: 1,
      },
    },
    aggs: {
      by_source_ip: {
        terms: { field: 'source.ip', size: 100 },
        aggs: {
          affected_host: { terms: { field: 'host.name', size: 1 } },
          top_evidence: {
            top_hits: { size: 5, sort: [{ '@timestamp': 'desc' }] },
          },
        },
      },
    },
  });

  const buckets = res.aggregations?.by_source_ip?.buckets ?? [];

  return buildCandidatesFromBuckets(buckets);
}

export function buildCandidatesFromBuckets(buckets) {
  return buckets.map((bucket) => ({
    rule_id: RULE_ID,
    rule_name: RULE_NAME,
    severity: SEVERITY,
    source_ip: bucket.key,
    affected_host: bucket.affected_host.buckets[0]?.key ?? null,
    affected_user: null,
    evidence: bucket.top_evidence.hits.hits.map((h) => h._source),
  }));
}
