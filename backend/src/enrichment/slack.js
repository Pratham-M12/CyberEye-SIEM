import axios from 'axios';
import 'dotenv/config';

const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL; // API required here
const DASHBOARD_BASE_URL = process.env.DASHBOARD_BASE_URL || 'http://localhost:5173';

// In-memory cache to prevent duplicate Slack notifications for the same alert ID
// (defense-in-depth on top of alerts/writer.js deduplication)
const notifiedAlertIds = new Map();
const DEDUPE_TTL_MS = 10 * 60 * 1000;

function isDuplicateNotification(alertId) {
  if (!alertId) return false;
  const now = Date.now();
  for (const [id, ts] of notifiedAlertIds.entries()) {
    if (now - ts > DEDUPE_TTL_MS) {
      notifiedAlertIds.delete(id);
    }
  }
  if (notifiedAlertIds.has(alertId)) {
    return true;
  }
  notifiedAlertIds.set(alertId, now);
  return false;
}

/**
 * Formats a critical alert into a rich Slack notification text containing
 * CyberEye branding, rule ID/name, severity, host, IP, user, MITRE technique,
 * timestamp, evidence context, and dashboard deep link.
 */
export function formatSlackMessage(alert) {
  const deepLink = `${DASHBOARD_BASE_URL}/alerts/${alert.id ?? ''}`;
  const ruleDisplay = alert.rule_id ? `[${alert.rule_id}] ${alert.rule_name}` : alert.rule_name;
  const severityDisplay = (alert.severity || 'critical').toUpperCase();

  const lines = [
    `:rotating_light: *[CyberEye SIEM] Critical Security Alert*`,
    `*Rule:* ${ruleDisplay}`,
    `*Severity:* ${severityDisplay}`,
    `*Host:* ${alert.affected_host ?? 'unknown'}`,
    `*Source IP:* ${alert.source_ip ?? 'unknown'}`,
  ];

  if (alert.affected_user) {
    lines.push(`*User:* ${alert.affected_user}`);
  }

  if (alert.mitre_technique_id || alert.mitre_technique_name) {
    const mitreParts = [alert.mitre_technique_id, alert.mitre_technique_name].filter(Boolean).join(' - ');
    const tactic = alert.mitre_tactic ? ` (${alert.mitre_tactic})` : '';
    lines.push(`*MITRE ATT&CK:* ${mitreParts}${tactic}`);
  }

  const timestamp = alert['@timestamp'] || alert.createdAt;
  if (timestamp) {
    lines.push(`*Timestamp:* ${timestamp}`);
  }

  if (Array.isArray(alert.evidence) && alert.evidence.length > 0) {
    lines.push(`*Evidence:* ${alert.evidence.length} correlated event(s)`);
  }

  lines.push(`<${deepLink}|View in CyberEye Dashboard>`);

  return { text: lines.join('\n') };
}

/**
 * POSTs a critical-severity alert to the configured Slack incoming webhook.
 * No-ops (with a console warning) until a real webhook URL is set in .env.
 * Catches delivery errors gracefully so the rule engine is never interrupted,
 * and ensures webhook secrets are never exposed in error logs.
 */
export async function notifySlack(alert) {
  if (!SLACK_WEBHOOK_URL || SLACK_WEBHOOK_URL === 'API required here') {
    console.warn('[slack] SLACK_WEBHOOK_URL not configured — skipping notification');
    return false;
  }

  if (alert?.id && isDuplicateNotification(alert.id)) {
    console.log(`[slack] skipping duplicate notification for alert: ${alert.id}`);
    return false;
  }

  const payload = formatSlackMessage(alert);

  try {
    await axios.post(SLACK_WEBHOOK_URL, payload, {
      timeout: 5000,
      headers: { 'Content-Type': 'application/json' },
    });
    return true;
  } catch (err) {
    // Sanitize error message to ensure webhook URL is never exposed
    const reason = err.response?.status
      ? `HTTP ${err.response.status} (${err.response.statusText || 'Error'})`
      : err.message || 'Network error';
    console.error(`[slack] notification delivery failed: ${reason}`);
    return false;
  }
}

export { notifiedAlertIds };

