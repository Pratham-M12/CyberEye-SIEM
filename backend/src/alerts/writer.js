// backend/src/alerts/writer.js
import { esClient, ALERTS_INDEX } from '../es/client.js';
import { MITRE_MAP } from '../rules/mitre.js';
import { notifySlack } from '../enrichment/slack.js';

// Suppress duplicate open alerts for the same rule + entity within this many
// seconds, so a sustained attack does not fire on every cron tick. Source IP
// is preferred; host/user is used when an alert has no IP.
const DEDUPE_WINDOW = '5m';

/**
 * Takes the raw candidate alerts returned by a rule module's run(), filters
 * out ones that duplicate a recent open alert, writes the rest to
 * siem-alerts, and pushes each new one to connected dashboards over
 * WebSocket. Returns the list of alerts actually written.
 */
export async function writeAlerts(candidates, io) {
  const written = [];

  for (const candidate of candidates) {
    const isDuplicate = await hasRecentAlert(candidate);
    if (isDuplicate) continue;

    const mitre = MITRE_MAP[candidate.rule_id] ?? {};
    const now = new Date().toISOString();
    const doc = {
      '@timestamp': now,
      createdAt: now,
      updatedAt: now,
      updatedBy: 'system',
      status: 'open',
      history: [
        {
          action: 'created',
          status: 'open',
          by: 'system',
          timestamp: now,
        },
      ],
      rule_id: candidate.rule_id,
      rule_name: candidate.rule_name,
      severity: candidate.severity,
      affected_host: candidate.affected_host,
      affected_user: candidate.affected_user,
      source_ip: candidate.source_ip,
      evidence: candidate.evidence ?? [],
      mitre_technique_id: mitre.id ?? null,
      mitre_technique_name: mitre.name ?? null,
      mitre_tactic: mitre.tactic ?? null,
    };

    const res = await esClient.index({
      index: ALERTS_INDEX,
      document: doc,
      refresh: 'wait_for',
    });

    const alert = { id: res._id, ...doc };
    written.push(alert);

    io?.emit('new_alert', alert);

    if (alert.severity === 'critical') {
      // Fire-and-forget; a Slack failure should never break the rule engine.
      notifySlack(alert).catch((err) =>
        console.error('[slack] notify failed:', err.message)
      );
    }
  }

  return written;
}

export async function hasRecentAlert(candidate) {
  const entityFilter = buildEntityFilter(candidate);
  if (!entityFilter) return false;

  const res = await esClient.search({
    index: ALERTS_INDEX,
    size: 0,
    track_total_hits: true,
    query: {
      bool: {
        filter: [
          { term: { rule_id: candidate.rule_id } },
          { term: { status: 'open' } },
          entityFilter,
          { range: { '@timestamp': { gte: `now-${DEDUPE_WINDOW}` } } },
        ],
      },
    },
  });

  return res.hits.total.value > 0;
}

export function buildEntityFilter({ source_ip: sourceIp, affected_host: affectedHost, affected_user: affectedUser }) {
  if (sourceIp) return { term: { source_ip: sourceIp } };

  const fallback = [];
  if (affectedHost) fallback.push({ term: { affected_host: affectedHost } });
  if (affectedUser) fallback.push({ term: { affected_user: affectedUser } });
  return fallback.length ? { bool: { filter: fallback } } : null;
}
