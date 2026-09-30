import axios from 'axios';
import 'dotenv/config';

const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL; // API required here
const DASHBOARD_BASE_URL = process.env.DASHBOARD_BASE_URL || 'http://localhost:5173';

/**
 * POSTs a critical-severity alert to the configured Slack incoming webhook.
 * No-ops (with a console warning) until a real webhook URL is set in .env —
 * this keeps local dev from crashing when the Phase 4 integration isn't
 * wired up yet.
 */
export async function notifySlack(alert) {
  if (!SLACK_WEBHOOK_URL || SLACK_WEBHOOK_URL === 'API required here') {
    console.warn('[slack] SLACK_WEBHOOK_URL not configured — skipping notification');
    return;
  }

  const deepLink = `${DASHBOARD_BASE_URL}/alerts/${alert.id}`;

  await axios.post(SLACK_WEBHOOK_URL, {
    text:
      `:rotating_light: *Critical alert: ${alert.rule_name}*\n` +
      `Host: ${alert.affected_host ?? 'unknown'}\n` +
      `Source IP: ${alert.source_ip ?? 'unknown'}\n` +
      `<${deepLink}|View in dashboard>`,
  });
}
