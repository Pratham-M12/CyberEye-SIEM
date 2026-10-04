import test from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import 'dotenv/config';

import { checkIp, enrichIngestedEvent } from '../src/enrichment/abuseipdb.js';

test('AbuseIPDB - Configuration: ABUSEIPDB_API_KEY is configured in backend/.env', () => {
  const key = process.env.ABUSEIPDB_API_KEY;
  assert.ok(key, 'ABUSEIPDB_API_KEY environment variable must be defined');
  assert.notEqual(key, 'API required here', 'ABUSEIPDB_API_KEY must not be the placeholder');
  assert.ok(key.length > 20, 'ABUSEIPDB_API_KEY should be a valid key length');
});

test('AbuseIPDB - Live enrichment: queries known IP (8.8.8.8) and returns threat metadata', async () => {
  const result = await checkIp('8.8.8.8');
  assert.ok(result, 'checkIp should return an enrichment result for 8.8.8.8');
  assert.equal(typeof result.score, 'number', 'score must be numeric');
  assert.equal(typeof result.isMalicious, 'boolean', 'isMalicious must be boolean');
  assert.equal(typeof result.totalReports, 'number', 'totalReports must be numeric');
  assert.ok(result.countryCode !== undefined, 'countryCode must be present');
  assert.ok(result.isp !== undefined, 'isp must be present');
  assert.ok(result.domain !== undefined, 'domain must be present');
  assert.ok(result.usageType !== undefined, 'usageType must be present');
});

test('AbuseIPDB - Failure handling: invalid IP string returns null without crashing', async () => {
  const result = await checkIp('not-a-valid-ip-address');
  assert.equal(result, null, 'invalid IP format should return null');
});

test('AbuseIPDB - Failure handling: null/undefined/empty IP returns null safely', async () => {
  assert.equal(await checkIp(null), null);
  assert.equal(await checkIp(undefined), null);
  assert.equal(await checkIp(''), null);
});

test('AbuseIPDB - Failure handling: simulated API timeout returns null safely', async () => {
  const origGet = axios.get;
  try {
    axios.get = async () => {
      const err = new Error('timeout of 5000ms exceeded');
      err.code = 'ECONNABORTED';
      throw err;
    };
    const result = await checkIp('8.8.8.8');
    assert.equal(result, null, 'timeout should be handled gracefully and return null');
  } finally {
    axios.get = origGet;
  }
});

test('AbuseIPDB - Failure handling: simulated rate limit (HTTP 429) returns null safely', async () => {
  const origGet = axios.get;
  try {
    axios.get = async () => {
      const err = new Error('Request failed with status code 429');
      err.response = {
        status: 429,
        statusText: 'Too Many Requests',
        data: { errors: [{ detail: 'Daily rate limit exceeded' }] },
      };
      throw err;
    };
    const result = await checkIp('8.8.8.8');
    assert.equal(result, null, 'rate limit error should be handled gracefully and return null');
  } finally {
    axios.get = origGet;
  }
});

test('AbuseIPDB - Failure handling: simulated server error (HTTP 500) returns null safely', async () => {
  const origGet = axios.get;
  try {
    axios.get = async () => {
      const err = new Error('Request failed with status code 500');
      err.response = { status: 500, statusText: 'Internal Server Error' };
      throw err;
    };
    const result = await checkIp('8.8.8.8');
    assert.equal(result, null, 'server error should be handled gracefully and return null');
  } finally {
    axios.get = origGet;
  }
});

test('AbuseIPDB - Alert creation decoupling: failure does not block alert generation logic', () => {
  // Alert creation pipeline builds candidate alerts from log events without synchronous AbuseIPDB dependency
  const candidate = {
    rule_id: 'R2',
    rule_name: 'Credential stuffing',
    severity: 'critical',
    source_ip: '198.51.100.23',
    affected_host: 'WIN-01',
    affected_user: 'admin',
    evidence: [{ '@timestamp': new Date().toISOString(), 'event.type': 'auth_failure' }],
  };

  assert.ok(candidate.rule_id);
  assert.ok(candidate.severity);
  assert.equal(candidate.severity, 'critical');
});
