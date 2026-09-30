import test from 'node:test';
import assert from 'node:assert/strict';
import { esClient } from '../src/es/client.js';

async function simulate(pipelineId, docs) {
  const res = await esClient.ingest.simulate({
    id: pipelineId,
    docs: docs.map((_source) => ({ _source })),
  });
  return res.docs.map((d) => d.doc?._source || d);
}

test('siem-snort-normalize parses raw fast-alert messages into canonical network fields', async () => {
  const docs = [
    {
      message:
        '09/30-20:15:00.123456 [**] [1:1000001:1] Portscan [**] [Priority: 2] {TCP} 203.0.113.77:45234 -> 10.0.0.15:80',
    },
    {
      message: '[Priority: 1] {TCP} 198.51.100.99:1234 -> 10.0.0.20:443',
    },
    {
      message: '203.0.113.77:50000 -> 10.0.0.15:8080',
    },
  ];

  const results = await simulate('siem-snort-normalize', docs);

  // Doc 1: Priority 2 -> high severity
  assert.equal(results[0].log?.source, 'snort');
  assert.equal(results[0].source?.ip, '203.0.113.77');
  assert.equal(results[0].source?.port, 45234);
  assert.equal(results[0].destination?.ip, '10.0.0.15');
  assert.equal(results[0].destination?.port, 80);
  assert.equal(results[0].event?.type, 'network_intrusion');
  assert.equal(results[0].event?.severity, 'high');

  // Doc 2: Priority 1 -> critical severity
  assert.equal(results[1].source?.ip, '198.51.100.99');
  assert.equal(results[1].destination?.port, 443);
  assert.equal(results[1].event?.severity, 'critical');

  // Doc 3: Fallback priority -> high severity
  assert.equal(results[2].source?.ip, '203.0.113.77');
  assert.equal(results[2].destination?.port, 8080);
  assert.equal(results[2].event?.severity, 'high');
});

test('siem-web-normalize parses raw access logs and detects SQLi / XSS attacks', async () => {
  const docs = [
    {
      event: { module: 'nginx' },
      message:
        '192.0.2.44 - - [30/Sep/2026:14:11:41 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512',
    },
    {
      event: { module: 'apache' },
      message:
        '192.0.2.44 - frank [30/Sep/2026:14:11:41 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 1024',
    },
    {
      event: { module: 'nginx' },
      message:
        '192.0.2.44 - - [30/Sep/2026:14:11:41 +0000] "GET /login.php?user=admin\'-- HTTP/1.1" 200 512',
    },
    {
      event: { module: 'nginx' },
      message:
        '10.0.0.99 - - [30/Sep/2026:14:11:41 +0000] "GET /index.html HTTP/1.1" 200 4096',
    },
  ];

  const results = await simulate('siem-web-normalize', docs);

  // Doc 1: XSS -> web_attack, medium, nginx
  assert.equal(results[0].log?.source, 'nginx');
  assert.equal(results[0].source?.ip, '192.0.2.44');
  assert.equal(results[0].http?.uri, '/search?q=<script>alert(1)</script>');
  assert.equal(results[0].event?.type, 'web_attack');
  assert.equal(results[0].event?.severity, 'medium');

  // Doc 2: SQLi UNION SELECT (URL-decoded) -> web_attack, medium, apache
  assert.equal(results[1].log?.source, 'apache');
  assert.equal(results[1].source?.ip, '192.0.2.44');
  assert.equal(
    results[1].http?.uri,
    '/products?id=1 UNION SELECT username,password FROM users'
  );
  assert.equal(results[1].event?.type, 'web_attack');
  assert.equal(results[1].event?.severity, 'medium');

  // Doc 3: SQLi admin'-- -> web_attack, medium
  assert.equal(results[2].http?.uri, "/login.php?user=admin'--");
  assert.equal(results[2].event?.type, 'web_attack');
  assert.equal(results[2].event?.severity, 'medium');

  // Doc 4: Benign request -> web_request, low
  assert.equal(results[3].source?.ip, '10.0.0.99');
  assert.equal(results[3].http?.uri, '/index.html');
  assert.equal(results[3].event?.type, 'web_request');
  assert.equal(results[3].event?.severity, 'low');
});

test('siem-syslog-normalize parses raw syslog and auth logs into canonical host, auth, and privilege fields', async () => {
  const docs = [
    {
      message:
        'Sep 30 14:10:00 ubuntu-vm sshd[1234]: Failed password for invalid user admin from 198.51.100.50 port 44222 ssh2',
    },
    {
      message:
        'Sep 30 14:10:05 ubuntu-vm sshd[1234]: Failed password for root from 198.51.100.50 port 44224 ssh2',
    },
    {
      message:
        'Sep 30 14:11:00 ubuntu-vm sshd[1234]: Accepted password for ubuntu from 198.51.100.50 port 44226 ssh2',
    },
    {
      message:
        'Sep 30 14:12:00 ubuntu-vm sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash',
    },
    {
      message:
        'Sep 30 14:13:00 ubuntu-vm kernel: [   12.345678] systemd[1]: Started User Manager for UID 1000.',
    },
  ];

  const results = await simulate('siem-syslog-normalize', docs);

  // Doc 1: Failed password for invalid user
  assert.equal(results[0].log?.source, 'syslog');
  assert.equal(results[0].host?.name, 'ubuntu-vm');
  assert.equal(results[0].user?.name, 'admin');
  assert.equal(results[0].source?.ip, '198.51.100.50');
  assert.equal(results[0].event?.type, 'auth_failure');
  assert.equal(results[0].event?.severity, 'medium');

  // Doc 2: Failed password for root
  assert.equal(results[1].user?.name, 'root');
  assert.equal(results[1].source?.ip, '198.51.100.50');
  assert.equal(results[1].event?.type, 'auth_failure');
  assert.equal(results[1].event?.severity, 'medium');

  // Doc 3: Accepted password
  assert.equal(results[2].user?.name, 'ubuntu');
  assert.equal(results[2].source?.ip, '198.51.100.50');
  assert.equal(results[2].event?.type, 'auth_success');
  assert.equal(results[2].event?.severity, 'low');

  // Doc 4: Sudo privilege assignment
  assert.equal(results[3].user?.name, 'ubuntu');
  assert.equal(results[3].event?.type, 'privilege_assigned');
  assert.equal(results[3].event?.severity, 'high');

  // Doc 5: Generic kernel message
  assert.equal(results[4].host?.name, 'ubuntu-vm');
  assert.equal(results[4].event?.type, 'system_event');
  assert.equal(results[4].event?.severity, 'low');
});

test('siem-windows-normalize preserves Windows Event ID mapping', async () => {
  const docs = [
    {
      winlog: {
        event_id: '4625',
        computer_name: 'WIN-DC01',
        event_data: { TargetUserName: 'jsmith', IpAddress: '198.51.100.23' },
      },
      message: 'An account failed to log on: jsmith',
    },
    {
      winlog: {
        event_id: '4624',
        computer_name: 'WIN-DC01',
        event_data: { TargetUserName: 'jsmith', IpAddress: '198.51.100.23' },
      },
      message: 'An account was successfully logged on: jsmith',
    },
  ];

  const results = await simulate('siem-windows-normalize', docs);

  assert.equal(results[0].log?.source, 'windows');
  assert.equal(results[0].event?.type, 'auth_failure');
  assert.equal(results[0].event?.severity, 'medium');
  assert.equal(results[0].source?.ip, '198.51.100.23');
  assert.equal(results[0].user?.name, 'jsmith');
  assert.equal(results[0].host?.name, 'WIN-DC01');

  assert.equal(results[1].event?.type, 'auth_success');
  assert.equal(results[1].event?.severity, 'low');
});

test('siem-windows-normalize handles valid IP and ignores "-" IpAddress', async () => {
  const docs = [
    // Test A: Windows 4624 with IpAddress = "192.168.56.20"
    {
      winlog: {
        event_id: '4624',
        computer_name: 'WIN-LAB01',
        event_data: { TargetUserName: 'admin', IpAddress: '192.168.56.20' },
      },
      message: 'An account was successfully logged on: admin',
    },
    // Test B: Windows 4624 with IpAddress = "-"
    {
      winlog: {
        event_id: '4624',
        computer_name: 'WIN-LAB01',
        event_data: { TargetUserName: 'admin', IpAddress: '-' },
      },
      message: 'An account was successfully logged on: admin',
    },
    // Test C: Windows 4625 with IpAddress = "192.168.56.20"
    {
      winlog: {
        event_id: '4625',
        computer_name: 'WIN-LAB01',
        event_data: { TargetUserName: 'admin', IpAddress: '192.168.56.20' },
      },
      message: 'An account failed to log on: admin',
    },
  ];

  const results = await simulate('siem-windows-normalize', docs);

  // Test A
  assert.equal(results[0].log?.source, 'windows');
  assert.equal(results[0].event?.type, 'auth_success');
  assert.equal(results[0].event?.severity, 'low');
  assert.equal(results[0].source?.ip, '192.168.56.20');

  // Test B
  assert.equal(results[1].log?.source, 'windows');
  assert.equal(results[1].event?.type, 'auth_success');
  assert.equal(results[1].event?.severity, 'low');
  assert.equal(results[1].source?.ip, undefined);

  // Test C
  assert.equal(results[2].log?.source, 'windows');
  assert.equal(results[2].event?.type, 'auth_failure');
  assert.equal(results[2].event?.severity, 'medium');
  assert.equal(results[2].source?.ip, '192.168.56.20');
});
