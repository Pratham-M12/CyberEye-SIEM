import { esClient, LOGS_INDEX } from '../es/client.js';

export const RULE_ID = 'R5';
export const RULE_NAME = 'Privilege escalation';
export const SEVERITY = 'critical';

const WINDOW = '5m';

export const SYSTEM_SERVICE_ACCOUNTS = new Set([
  'SYSTEM',
  'LOCAL SERVICE',
  'NETWORK SERVICE',
  'ANONYMOUS LOGON',
]);

/**
 * Identifies routine Windows system, service, and machine accounts that
 * perform normal background privilege assignments and should not trigger R5.
 */
export function isSystemServiceAccount(user) {
  if (!user || typeof user !== 'string') return true;
  const trimmed = user.trim();
  if (!trimmed || trimmed === '-') return true;

  // Normalize by stripping domain/authority prefix (e.g. "NT AUTHORITY\SYSTEM" -> "SYSTEM")
  const baseUser = (trimmed.includes('\\') ? trimmed.split('\\').pop() : trimmed).toUpperCase();

  if (SYSTEM_SERVICE_ACCOUNTS.has(baseUser)) return true;
  if (baseUser.endsWith('$')) return true; // Machine/computer accounts
  if (/^DWM(-[0-9]+)?$/i.test(baseUser)) return true; // Desktop Window Manager
  if (/^UMFD(-[0-9]+)?$/i.test(baseUser)) return true; // User Mode Font Driver Host

  return false;
}

function getRecordId(event) {
  return (
    event['winlog.record_id'] ??
    event.winlog?.record_id ??
    event.record_id ??
    event['event.record_id'] ??
    null
  );
}

/**
 * Event ID 4672 (privilege_assigned) within 5 minutes after Event ID 4624
 * (auth_success) for the same user. Each privilege event is correlated to a
 * preceding login for a real non-system user identity.
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
        must_not: [
          { terms: { 'user.name': ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', '-'] } },
          { wildcard: { 'user.name': '*$' } },
          { wildcard: { 'user.name': 'DWM-*' } },
          { wildcard: { 'user.name': 'UMFD-*' } },
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
    if (isSystemServiceAccount(bucket.key)) continue;

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
              { range: { '@timestamp': { gte: windowStart, lte: privilegeAt } } },
            ],
          },
        },
        aggs: {
          latest_login: { top_hits: { size: 10, sort: [{ '@timestamp': 'desc' }] } },
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
  const user = privilegeEvent['user.name'] || privilegeEvent.user?.name;
  if (!Number.isFinite(privilegeAtMs) || !user) return null;
  if (isSystemServiceAccount(user)) return null;

  const privHost = privilegeEvent['host.name'] || privilegeEvent.host?.name;

  const login = loginEvents
    .filter((event) => {
      const loginAtMs = new Date(event['@timestamp']).getTime();
      const eventType = event['event.type'] || event.event?.type;
      const logSource = event['log.source'] || event.log?.source;
      const eventUser = event['user.name'] || event.user?.name;
      if (isSystemServiceAccount(eventUser)) return false;

      const isSameUser = eventUser === user || eventUser?.toLowerCase() === user?.toLowerCase();
      if (!isSameUser) return false;

      const eventHost = event['host.name'] || event.host?.name;
      if (privHost && eventHost && privHost.toLowerCase() !== eventHost.toLowerCase()) {
        return false;
      }

      if (
        eventType !== 'auth_success' ||
        logSource !== 'windows' ||
        !Number.isFinite(loginAtMs)
      ) {
        return false;
      }

      // Successful authentication must precede the privilege event within 5 minutes
      if (loginAtMs > privilegeAtMs || privilegeAtMs - loginAtMs > 5 * 60 * 1000) {
        return false;
      }

      // If recorded at the exact same millisecond, verify record IDs if available
      if (loginAtMs === privilegeAtMs) {
        const loginRec = getRecordId(event);
        const privRec = getRecordId(privilegeEvent);
        if (loginRec != null && privRec != null && Number(loginRec) > Number(privRec)) {
          return false;
        }
      }

      return true;
    })
    .sort((a, b) => {
      const timeDiff = new Date(b['@timestamp']) - new Date(a['@timestamp']);
      if (timeDiff !== 0) return timeDiff;
      const aRec = getRecordId(a);
      const bRec = getRecordId(b);
      if (aRec != null && bRec != null) {
        return Number(bRec) - Number(aRec);
      }
      return 0;
    })[0];

  if (!login) return null;

  const sourceIp = login['source.ip'] || login.source?.ip || null;
  const affectedHost = privHost || null;

  return {
    rule_id: RULE_ID,
    rule_name: RULE_NAME,
    severity: SEVERITY,
    source_ip: sourceIp,
    affected_host: affectedHost,
    affected_user: user,
    evidence: [login, privilegeEvent],
  };
}
