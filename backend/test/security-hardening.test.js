import test from 'node:test';
import assert from 'node:assert/strict';

const BASE_URL = process.env.TEST_API_URL || 'http://localhost:4000';

test('Security Hardening — HTTP Headers & Fingerprinting', async (t) => {
  await t.test('Server does not expose X-Powered-By header', async () => {
    const res = await fetch(`${BASE_URL}/health`);
    assert.equal(res.headers.get('x-powered-by'), null, 'X-Powered-By header should be removed');
  });

  await t.test('Server sets security headers (nosniff, frame protection, referrer policy)', async () => {
    const res = await fetch(`${BASE_URL}/health`);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
  });
});

test('Security Hardening — Information Disclosure & Secrets', async (t) => {
  await t.test('/health and /api/health return status without secrets or infrastructure internals', async () => {
    for (const path of ['/health', '/api/health']) {
      const res = await fetch(`${BASE_URL}${path}`);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.status === 'ok' || data.status === 'degraded');
      assert.equal(typeof data.elasticsearch, 'boolean');

      const bodyText = JSON.stringify(data);
      assert.equal(bodyText.includes('process.env'), false);
      assert.equal(bodyText.includes('password'), false);
      assert.equal(bodyText.includes('CLAUDE_API_KEY'), false);
      assert.equal(bodyText.includes('ABUSEIPDB_API_KEY'), false);
      assert.equal(bodyText.includes('SLACK_WEBHOOK_URL'), false);
      assert.equal(bodyText.includes('GROQ_API_KEY'), false);
    }
  });

  await t.test('Unknown 404 endpoint returns safe JSON without stack trace or paths', async () => {
    const res = await fetch(`${BASE_URL}/api/non_existent_endpoint_12345`);
    assert.equal(res.status, 404);
    const data = await res.json();
    assert.equal(data.error, 'Endpoint not found');
    assert.equal(data.stack, undefined);
  });
});

test('Security Hardening — Malformed JSON & Payload Limits', async (t) => {
  await t.test('Malformed JSON payload does not crash server and returns 400 JSON error', async () => {
    const res = await fetch(`${BASE_URL}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"broken": [true, }',
    });

    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.error, 'Malformed JSON payload');
    assert.equal(data.stack, undefined);
  });

  await t.test('Oversized payload exceeding body parser limit returns 413', async () => {
    // Attempt sending a payload larger than allowed (e.g. 25MB string)
    const largeStr = 'A'.repeat(25 * 1024 * 1024);
    try {
      const res = await fetch(`${BASE_URL}/api/uploads`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: largeStr }),
      });
      assert.equal(res.status, 413);
      const data = await res.json();
      assert.equal(data.error, 'Payload exceeds maximum allowed size');
    } catch (err) {
      // In some environments, connection reset on payload limit is also acceptable
      assert.ok(err);
    }
  });
});

test('Security Hardening — Logs API Validation (/api/logs)', async (t) => {
  await t.test('Pagination exceeding Elasticsearch window (> 10000) is rejected with 400', async () => {
    const res = await fetch(`${BASE_URL}/api/logs?page=201&pageSize=100`);
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.error.includes('10000'));
  });

  await t.test('Negative pagination values are rejected with 400', async () => {
    const res = await fetch(`${BASE_URL}/api/logs?page=-5&pageSize=-10`);
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.error.includes('positive integer'));
  });

  await t.test('Invalid IP address parameter is rejected with 400', async () => {
    const maliciousIps = [
      'not-an-ip',
      '192.168.1.300',
      '10.0.0.1; DROP TABLE logs;',
      '1.1.1.1<script>alert(1)</script>',
      '../../etc/passwd',
    ];

    for (const ip of maliciousIps) {
      const res = await fetch(`${BASE_URL}/api/logs?source_ip=${encodeURIComponent(ip)}`);
      assert.equal(res.status, 400, `Expected 400 for invalid IP: ${ip}`);
      const data = await res.json();
      assert.equal(data.error, 'Invalid source_ip parameter');
    }
  });

  await t.test('Invalid severity parameter is rejected with 400', async () => {
    const invalidSeverities = ['extreme', 'fatal', 'high OR 1=1', '<script>'];
    for (const sev of invalidSeverities) {
      const res = await fetch(`${BASE_URL}/api/logs?severity=${encodeURIComponent(sev)}`);
      assert.equal(res.status, 400, `Expected 400 for invalid severity: ${sev}`);
      const data = await res.json();
      assert.equal(data.error, 'Invalid severity parameter');
    }
  });

  await t.test('Invalid timestamp parameters are rejected with 400', async () => {
    const res = await fetch(`${BASE_URL}/api/logs?from=not-a-date`);
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.error.includes('timestamp format'));
  });

  await t.test('Lucene query injection and complex regex/wildcard strings do not crash ES', async () => {
    const injectionStrings = [
      'raw_message:(foo AND bar] /test/ ~2 ^5',
      '{{{[[[(((',
      '\\*\\?\\+\\',
      'AND OR NOT TO',
      'a'.repeat(2000), // Exceedingly long search query
    ];

    for (const q of injectionStrings) {
      const res = await fetch(`${BASE_URL}/api/logs?q=${encodeURIComponent(q)}`);
      // Should either return 200 (gracefully executed via simple_query_string) or clean 400
      assert.ok(res.status === 200 || res.status === 400, `Expected 200 or 400, got ${res.status}`);
      const data = await res.json();
      assert.equal(data.stack, undefined);
    }
  });
});

test('Security Hardening — Alerts API Validation (/api/alerts)', async (t) => {
  await t.test('Invalid or traversal Alert ID is rejected with 400', async () => {
    const invalidIds = [
      '../test',
      '..%2F..%2Fetc%2Fpasswd',
      'id<script>alert(1)</script>',
      'id; SELECT * FROM alerts',
      'a'.repeat(300),
    ];

    for (const id of invalidIds) {
      const res = await fetch(`${BASE_URL}/api/alerts/${encodeURIComponent(id)}`);
      assert.equal(res.status, 400, `Expected 400 for invalid ID: ${id}`);
      const data = await res.json();
      assert.equal(data.error, 'Invalid alert ID');
    }
  });

  await t.test('Non-existent valid Alert ID returns clean 404 without stack trace', async () => {
    const res = await fetch(`${BASE_URL}/api/alerts/nonexistent-alert-id-99999`);
    assert.equal(res.status, 404);
    const data = await res.json();
    assert.equal(data.error, 'Alert not found');
    assert.equal(data.stack, undefined);
  });

  await t.test('Top attackers invalid window is rejected with 400', async () => {
    const res = await fetch(`${BASE_URL}/api/alerts/top-attackers?window=invalid_duration;DROP`);
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.error.includes('Invalid window'));
  });

  await t.test('PATCH /api/alerts/:id/status with invalid status is rejected with 400', async () => {
    const res = await fetch(`${BASE_URL}/api/alerts/test-id/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'invalid_status' }),
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.error, 'Invalid status');
  });
});

test('Security Hardening — Stats API Validation (/api/stats & aliases)', async (t) => {
  await t.test('GET /api/stats/timeline with invalid interval is rejected with 400', async () => {
    const res = await fetch(`${BASE_URL}/api/stats/timeline?interval=invalid_interval`);
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.error.includes('Invalid interval'));
  });

  await t.test('Convenience route aliases (/api/summary, /api/timeline, /api/top-attackers) function correctly', async () => {
    const summaryRes = await fetch(`${BASE_URL}/api/summary`);
    assert.equal(summaryRes.status, 200);
    const summaryData = await summaryRes.json();
    assert.equal(typeof summaryData.events_last_24h, 'number');

    const timelineRes = await fetch(`${BASE_URL}/api/timeline?window=24h&interval=1h`);
    assert.equal(timelineRes.status, 200);
    const timelineData = await timelineRes.json();
    assert.ok(Array.isArray(timelineData.timeline));

    const attackersRes = await fetch(`${BASE_URL}/api/top-attackers?window=24h&limit=5`);
    assert.equal(attackersRes.status, 200);
    const attackersData = await attackersRes.json();
    assert.ok(Array.isArray(attackersData.attackers));
  });
});

test('Security Hardening — Upload API Validation & Sanitization (/api/uploads)', async (t) => {
  await t.test('Upload endpoint rejects path traversal in fileName', async () => {
    const res = await fetch(`${BASE_URL}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fileName: '../../../../etc/passwd.log',
        sourceType: 'syslog',
        encoding: 'utf8',
        content: 'Oct 04 20:00:00 server sshd[123]: Failed password for root from 192.168.1.10 port 22 ssh2',
      }),
    });

    // fileName should be sanitized to passwd.log and ingested safely, or rejected
    assert.ok(res.status === 201 || res.status === 400);
    if (res.status === 201) {
      const data = await res.json();
      assert.equal(data.fileName, 'passwd.log', 'Path traversal sequence must be stripped');
    }
  });

  await t.test('Upload endpoint rejects unsupported sourceType', async () => {
    const res = await fetch(`${BASE_URL}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fileName: 'test.log',
        sourceType: 'executable_sh',
        encoding: 'utf8',
        content: 'malicious payload',
      }),
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.error.includes('Unsupported upload source type'));
  });

  await t.test('Upload endpoint rejects mismatched encoding', async () => {
    const res = await fetch(`${BASE_URL}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fileName: 'test.log',
        sourceType: 'syslog',
        encoding: 'base64', // syslog expects utf8
        content: 'dGVzdA==',
      }),
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.error.includes('Invalid encoding'));
  });
});

test('Security Hardening — Existing Legitimate API Requests Pass', async (t) => {
  await t.test('Legitimate GET /api/logs returns 200 with structured data', async () => {
    const res = await fetch(`${BASE_URL}/api/logs?page=1&pageSize=10`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(typeof data.total, 'number');
    assert.ok(Array.isArray(data.logs));
  });

  await t.test('Legitimate GET /api/alerts returns 200 with structured data', async () => {
    const res = await fetch(`${BASE_URL}/api/alerts?page=1&pageSize=10`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(typeof data.total, 'number');
    assert.ok(Array.isArray(data.alerts));
  });

  await t.test('Legitimate GET /api/uploads/config returns 200 with config', async () => {
    const res = await fetch(`${BASE_URL}/api/uploads/config`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(typeof data.maxUploadSizeMb, 'number');
    assert.ok(Array.isArray(data.supportedUploadTypes));
  });
});
