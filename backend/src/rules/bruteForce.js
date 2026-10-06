import { esClient, LOGS_INDEX } from '../es/client.js';

export const RULE_ID = 'R1';
export const RULE_NAME = 'Brute-force login';
export const SEVERITY = 'high';

const WINDOW = '60s';
const THRESHOLD = 5;

/**
 * >= 5 Windows Event ID 4625 (auth_failure) from the same source IP within
 * 60 seconds. Pure aggregation query — no in-memory event buffering — so the
 * rule engine stays stateless and restartable.
 */
export async function run() {
  const res = await esClient.search({
    index: LOGS_INDEX,
    size: 0,
    query: {
      bool: {
        filter: [
          { term: { 'event.type': 'auth_failure' } },
          { term: { 'log.source': 'windows' } },
          { range: { '@timestamp': { gte: `now-${WINDOW}` } } },
        ],
      },
    },
    aggs: {
      by_source_ip: {
        terms: { field: 'source.ip', min_doc_count: THRESHOLD, size: 100 },
        aggs: {
          affected_host: { terms: { field: 'host.name', size: 1 } },
          affected_user: { terms: { field: 'user.name', size: 1 } },
          top_evidence: {
            top_hits: { size: 5, sort: [{ '@timestamp': 'desc' }] },
          },
          last_failure: { max: { field: '@timestamp' } },
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
    affected_user: bucket.affected_user.buckets[0]?.key ?? null,
    evidence: bucket.top_evidence.hits.hits.map((h) => h._source),
    fail_count: bucket.doc_count,
    last_failure_at: bucket.last_failure?.value_as_string ?? null,
  }));
}

// Pure counterpart to the aggregation result mapper, used by deterministic
// tests to verify the canonical event vocabulary and 60-second threshold.
export function buildCandidatesFromEvents(events, referenceTime = Date.now()) {
  const windowStart = referenceTime - 60 * 1000;
  const bySourceIp = new Map();

  for (const event of events) {
    const timestamp = new Date(event['@timestamp']).getTime();
    const sourceIp = event['source.ip'] || event.source?.ip;
    const eventType = event['event.type'] || event.event?.type;
    const logSource = event['log.source'] || event.log?.source;
    if (
      eventType !== 'auth_failure' ||
      logSource !== 'windows' ||
      !sourceIp ||
      !Number.isFinite(timestamp) ||
      timestamp < windowStart ||
      timestamp > referenceTime
    ) {
      continue;
    }

    const group = bySourceIp.get(sourceIp) ?? [];
    group.push(event);
    bySourceIp.set(sourceIp, group);
  }

  return buildCandidatesFromBuckets(
    [...bySourceIp.entries()]
      .filter(([, groupedEvents]) => groupedEvents.length >= THRESHOLD)
      .map(([sourceIp, groupedEvents]) => {
        const newestFirst = [...groupedEvents].sort(
          (a, b) => new Date(b['@timestamp']) - new Date(a['@timestamp'])
        );
        const hostName = groupedEvents[0]['host.name'] || groupedEvents[0].host?.name;
        const userName = groupedEvents[0]['user.name'] || groupedEvents[0].user?.name;
        return {
          key: sourceIp,
          doc_count: groupedEvents.length,
          affected_host: { buckets: hostName ? [{ key: hostName }] : [] },
          affected_user: { buckets: userName ? [{ key: userName }] : [] },
          top_evidence: { hits: { hits: newestFirst.slice(0, 5).map((_source) => ({ _source })) } },
          last_failure: { value_as_string: newestFirst[0]['@timestamp'] },
        };
      })
  );
}

// Builds every qualifying rolling 60-second burst in a supplied event set.
// R2 uses this across its five-minute correlation horizon; R1 itself remains
// an Elasticsearch aggregation over the current 60-second detection window.
export function buildRollingBurstCandidates(events) {
  const bySourceIp = new Map();

  for (const event of events) {
    const sourceIp = event['source.ip'] || event.source?.ip;
    const eventType = event['event.type'] || event.event?.type;
    const logSource = event['log.source'] || event.log?.source;
    const timestamp = new Date(event['@timestamp']).getTime();
    if (
      eventType !== 'auth_failure' ||
      logSource !== 'windows' ||
      !sourceIp ||
      !Number.isFinite(timestamp)
    ) {
      continue;
    }
    const group = bySourceIp.get(sourceIp) ?? [];
    group.push(event);
    bySourceIp.set(sourceIp, group);
  }

  const candidates = [];
  for (const [sourceIp, groupedEvents] of bySourceIp) {
    const ordered = [...groupedEvents].sort(
      (a, b) => new Date(a['@timestamp']) - new Date(b['@timestamp'])
    );
    let windowStartIndex = 0;

    for (let endIndex = 0; endIndex < ordered.length; endIndex += 1) {
      const endMs = new Date(ordered[endIndex]['@timestamp']).getTime();
      while (
        endMs - new Date(ordered[windowStartIndex]['@timestamp']).getTime() > 60 * 1000
      ) {
        windowStartIndex += 1;
      }

      const burstEvents = ordered.slice(windowStartIndex, endIndex + 1);
      if (burstEvents.length < THRESHOLD) continue;

      const newestFirst = [...burstEvents].reverse();
      const hostName = ordered[endIndex]['host.name'] || ordered[endIndex].host?.name;
      const userName = ordered[endIndex]['user.name'] || ordered[endIndex].user?.name;
      candidates.push({
        rule_id: RULE_ID,
        rule_name: RULE_NAME,
        severity: SEVERITY,
        source_ip: sourceIp,
        affected_host: hostName ?? null,
        affected_user: userName ?? null,
        evidence: newestFirst.slice(0, 5),
        fail_count: burstEvents.length,
        last_failure_at: ordered[endIndex]['@timestamp'],
      });
    }
  }

  return candidates;
}
