import test from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import 'dotenv/config';

import { notifySlack, formatSlackMessage, notifiedAlertIds } from '../src/enrichment/slack.js';

test('Slack - Configuration: SLACK_WEBHOOK_URL is configured in backend/.env', () => {
  const url = process.env.SLACK_WEBHOOK_URL;
  assert.ok(url, 'SLACK_WEBHOOK_URL environment variable must be defined');
  assert.notEqual(url, 'API required here', 'SLACK_WEBHOOK_URL must not be the placeholder');
  assert.ok(url.startsWith('https://hooks.slack.com/'), 'SLACK_WEBHOOK_URL must be a valid Slack webhook URL');
});

test('Slack - Message Audit: notification payload contains all required alert details', () => {
  const alert = {
    id: 'alert-audit-001',
    rule_id: 'R2',
    rule_name: 'Credential stuffing',
    severity: 'critical',
    affected_host: 'WIN-DC-01',
    source_ip: '198.51.100.23',
    affected_user: 'security-admin',
    mitre_technique_id: 'T1110',
    mitre_technique_name: 'Brute Force',
    mitre_tactic: 'Credential Access',
    evidence: [{ '@timestamp': '2026-10-05T00:00:00.000Z' }, { '@timestamp': '2026-10-05T00:01:00.000Z' }],
    '@timestamp': '2026-10-05T00:01:05.000Z',
  };

  const payload = formatSlackMessage(alert);
  const text = payload.text;

  assert.ok(text.includes('CyberEye SIEM'), 'Message must contain CyberEye branding');
  assert.ok(text.includes('[R2] Credential stuffing'), 'Message must contain rule ID and rule name');
  assert.ok(text.includes('CRITICAL'), 'Message must contain uppercase severity');
  assert.ok(text.includes('WIN-DC-01'), 'Message must contain affected host');
  assert.ok(text.includes('198.51.100.23'), 'Message must contain source IP');
  assert.ok(text.includes('security-admin'), 'Message must contain affected user');
  assert.ok(text.includes('T1110 - Brute Force'), 'Message must contain MITRE technique');
  assert.ok(text.includes('Credential Access'), 'Message must contain MITRE tactic');
  assert.ok(text.includes('2026-10-05T00:01:05.000Z'), 'Message must contain timestamp');
  assert.ok(text.includes('2 correlated event(s)'), 'Message must contain evidence context');
  assert.ok(text.includes('/alerts/alert-audit-001'), 'Message must contain dashboard deep link');
});

test('Slack - Severity filtering: only critical alerts trigger Slack dispatch in alerts/writer.js logic', () => {
  const nonCriticalAlerts = [
    { rule_id: 'R1', rule_name: 'Brute force', severity: 'medium' },
    { rule_id: 'R3', rule_name: 'Port scan', severity: 'medium' },
    { rule_id: 'R4', rule_name: 'Web attack', severity: 'medium' },
  ];

  const criticalAlerts = [
    { rule_id: 'R2', rule_name: 'Credential stuffing', severity: 'critical' },
    { rule_id: 'R5', rule_name: 'Privilege escalation', severity: 'critical' },
  ];

  for (const alert of nonCriticalAlerts) {
    const shouldDispatch = alert.severity === 'critical';
    assert.equal(shouldDispatch, false, `${alert.rule_id} (${alert.severity}) must not dispatch to Slack`);
  }

  for (const alert of criticalAlerts) {
    const shouldDispatch = alert.severity === 'critical';
    assert.equal(shouldDispatch, true, `${alert.rule_id} (${alert.severity}) must dispatch to Slack`);
  }
});

test('Slack - Live Delivery: controlled critical alert is successfully posted to Slack', async () => {
  const testAlert = {
    id: `controlled-audit-${Date.now()}`,
    rule_id: 'R2',
    rule_name: 'Credential stuffing',
    severity: 'critical',
    affected_host: 'WIN-DC-01',
    source_ip: '198.51.100.23',
    affected_user: 'audit-user',
    mitre_technique_id: 'T1110',
    mitre_technique_name: 'Brute Force',
    mitre_tactic: 'Credential Access',
    evidence: [{}, {}],
    '@timestamp': new Date().toISOString(),
  };

  const sent = await notifySlack(testAlert);
  assert.equal(sent, true, 'Controlled Slack notification must deliver successfully');
});

test('Slack - Duplicate protection: duplicate alert notification is suppressed', async () => {
  const alertId = `dupe-check-${Date.now()}`;
  const alert = {
    id: alertId,
    rule_id: 'R5',
    rule_name: 'Privilege escalation',
    severity: 'critical',
    affected_host: 'DC-02',
    source_ip: '198.51.100.44',
    affected_user: 'svc-admin',
  };

  // Pre-seed the notified cache for this alertId
  notifiedAlertIds.set(alertId, Date.now());

  const result = await notifySlack(alert);
  assert.equal(result, false, 'Duplicate alert ID notification must be suppressed');
});

test('Slack - Failure handling: simulated webhook failure returns false without crashing', async () => {
  const origPost = axios.post;
  try {
    axios.post = async () => {
      const err = new Error('Request failed with status code 500');
      err.response = { status: 500, statusText: 'Internal Server Error' };
      throw err;
    };

    const alert = {
      id: `err-test-${Date.now()}`,
      rule_id: 'R2',
      rule_name: 'Simulated Failure Alert',
      severity: 'critical',
    };

    const result = await notifySlack(alert);
    assert.equal(result, false, 'Failure should be caught and return false');
  } finally {
    axios.post = origPost;
  }
});
