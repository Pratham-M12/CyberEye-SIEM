import { esClient, LOGS_INDEX } from '../es/client.js';
import { buildRollingBurstCandidates } from './bruteForce.js';

export const RULE_ID = 'R2';
export const RULE_NAME = 'Credential stuffing';
export const SEVERITY = 'critical';

const SUCCESS_WINDOW = '5m';
const SUCCESS_WINDOW_MS = 5 * 60 * 1000;
const FAILURE_LOOKBACK = '6m';

/**
 * Escalation of R1: a brute-force burst (>=5 failures/60s) from a source IP,
 * followed by a successful login (Event ID 4624) from that *same* IP within
 * 5 minutes. It reconstructs rolling 60-second failure bursts from the
 * correlation horizon, then checks each one for an auth_success strictly
 * after its last failure. This allows a success near the end of the full
 * five-minute window to be detected after R1's 60-second live window ends.
 */
export async function run() {
  const failureRes = await esClient.search({
    index: LOGS_INDEX,
    size: 10_000,
    sort: [{ '@timestamp': 'asc' }],
    query: {
      bool: {
        filter: [
          { term: { 'event.type': 'auth_failure' } },
          { term: { 'log.source': 'windows' } },
          { range: { '@timestamp': { gte: `now-${FAILURE_LOOKBACK}` } } },
        ],
      },
    },
  });

  const bruteForceHits = buildRollingBurstCandidates(
    failureRes.hits.hits.map((hit) => hit._source)
  );
  if (bruteForceHits.length === 0) return [];

  const results = [];

  for (const hit of bruteForceHits) {
    const lastFailureAt = hit.last_failure_at || latestTimestamp(hit.evidence);
    if (!lastFailureAt) continue;

    const successDeadline = new Date(
      new Date(lastFailureAt).getTime() + SUCCESS_WINDOW_MS
    ).toISOString();

    const res = await esClient.search({
      index: LOGS_INDEX,
      size: 0,
      query: {
        bool: {
          filter: [
            { term: { 'log.source': 'windows' } },
            { term: { 'event.type': 'auth_success' } },
            { term: { 'source.ip': hit.source_ip } },
            { range: { '@timestamp': { gt: lastFailureAt, lte: successDeadline } } },
          ],
        },
      },
      aggs: {
        latest_success: {
          top_hits: { size: 3, sort: [{ '@timestamp': 'desc' }] },
        },
      },
    });

    const successEvents = (res.aggregations?.latest_success?.hits?.hits ?? []).map(
      (successHit) => successHit._source
    );
    results.push(...buildCandidatesForBurst(hit, successEvents));
  }

  return results;
}

export function buildCandidatesForBurst(bruteForceHit, successEvents) {
  const lastFailureAt = bruteForceHit.last_failure_at || latestTimestamp(bruteForceHit.evidence);
  if (!lastFailureAt) return [];

  const lastFailureMs = new Date(lastFailureAt).getTime();
  const success = successEvents
    .filter((event) => {
      const eventType = event['event.type'] || event.event?.type;
      const logSource = event['log.source'] || event.log?.source;
      const sourceIp = event['source.ip'] || event.source?.ip;
      return (
        eventType === 'auth_success' &&
        logSource === 'windows' &&
        sourceIp === bruteForceHit.source_ip &&
        isAfterWithinWindow(event['@timestamp'], lastFailureMs, SUCCESS_WINDOW_MS)
      );
    })
    .sort((a, b) => new Date(a['@timestamp']) - new Date(b['@timestamp']))[0];

  if (!success) return [];

  const successUser = (success['user.name'] || success.user?.name) ?? bruteForceHit.affected_user;

  return [{
    rule_id: RULE_ID,
    rule_name: RULE_NAME,
    severity: SEVERITY,
    source_ip: bruteForceHit.source_ip,
    affected_host: bruteForceHit.affected_host,
    affected_user: successUser,
    evidence: [...(bruteForceHit.evidence ?? []), success],
    fail_count: bruteForceHit.fail_count,
  }];
}

function latestTimestamp(events = []) {
  return events
    .map((event) => event['@timestamp'])
    .filter(Boolean)
    .sort((a, b) => new Date(b) - new Date(a))[0] ?? null;
}

function isAfterWithinWindow(timestamp, startMs, windowMs) {
  const timestampMs = new Date(timestamp).getTime();
  return Number.isFinite(timestampMs) && timestampMs > startMs && timestampMs - startMs <= windowMs;
}
