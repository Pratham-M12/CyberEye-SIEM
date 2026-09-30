import { esClient, LOGS_INDEX } from '../es/client.js';

export const RULE_ID = 'R5';
export const RULE_NAME = 'Privilege escalation';
export const SEVERITY = 'critical';

const WINDOW = '5m';

/**
 * Event ID 4672 (privilege_assigned) within 5 minutes after Event ID 4624
 * (auth_success) for the same user. Each privilege event is correlated to a
 * strictly earlier login rather than merely checking whether both exist.
 */
export async function run() {
  const res = await esClient.search({
    index: LOGS_INDEX,
    size: 0,
    query: {
      bool: {
        filter: [
          { term: { 'event.type': 'privilege_assigned' } },
          { term: { 'log.source': 'windows' } },
          { range: { '@timestamp': { gte: `now-${WINDOW}` } } },
        ],
      },
    },
    aggs: {
      by_user: {
        terms: { field: 'user.name', size: 100 },
        aggs: {
          affected_host: { terms: { field: 'host.name', size: 1 } },
          privilege_events: {
            top_hits: { size: 100, sort: [{ '@timestamp': 'desc' }] },
          },
        },
      },
    },
  });

  const buckets = res.aggregations?.by_user?.buckets ?? [];
  const results = [];

  for (const bucket of buckets) {
    const privilegeEvents = bucket.privilege_events?.hits?.hits.map((hit) => hit._source) ?? [];

    for (const privilegeEvent of privilegeEvents) {
      const privilegeAt = privilegeEvent['@timestamp'];
      if (!privilegeAt) continue;

      const windowStart = new Date(new Date(privilegeAt).getTime() - 5 * 60 * 1000).toISOString();
      const loginRes = await esClient.search({
        index: LOGS_INDEX,
        size: 0,
        query: {
          bool: {
            filter: [
              { term: { 'event.type': 'auth_success' } },
              { term: { 'log.source': 'windows' } },
              { term: { 'user.name': bucket.key } },
              { range: { '@timestamp': { gte: windowStart, lt: privilegeAt } } },
            ],
          },
        },
        aggs: {
          latest_login: { top_hits: { size: 1, sort: [{ '@timestamp': 'desc' }] } },
        },
      });

      const loginEvents = (loginRes.aggregations?.latest_login?.hits?.hits ?? []).map(
        (loginHit) => loginHit._source
      );
      const candidate = buildCandidateForPrivilegeEvent(privilegeEvent, loginEvents);
      if (candidate) results.push(candidate);
    }
  }

  return results;
}

export function buildCandidateForPrivilegeEvent(privilegeEvent, loginEvents) {
  const privilegeAtMs = new Date(privilegeEvent['@timestamp']).getTime();
  const user = privilegeEvent['user.name'];
  if (!Number.isFinite(privilegeAtMs) || !user) return null;

  const login = loginEvents
    .filter((event) => {
      const loginAtMs = new Date(event['@timestamp']).getTime();
      return (
        event['event.type'] === 'auth_success' &&
        event['log.source'] === 'windows' &&
        event['user.name'] === user &&
        Number.isFinite(loginAtMs) &&
        loginAtMs < privilegeAtMs &&
        privilegeAtMs - loginAtMs <= 5 * 60 * 1000
      );
    })
    .sort((a, b) => new Date(b['@timestamp']) - new Date(a['@timestamp']))[0];

  if (!login) return null;

  return {
    rule_id: RULE_ID,
    rule_name: RULE_NAME,
    severity: SEVERITY,
    source_ip: login['source.ip'] ?? null,
    affected_host: privilegeEvent['host.name'] ?? null,
    affected_user: user,
    evidence: [login, privilegeEvent],
  };
}
