import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildCandidatesFromBuckets as buildR1Candidates,
  buildCandidatesFromEvents,
  buildRollingBurstCandidates,
} from '../src/rules/bruteForce.js';
import { buildCandidatesForBurst } from '../src/rules/credentialStuffing.js';
import { buildCandidatesFromBuckets as buildR3Candidates } from '../src/rules/portScan.js';
import { buildCandidatesFromBuckets as buildR4Candidates } from '../src/rules/webAttack.js';
import { buildCandidateForPrivilegeEvent } from '../src/rules/privEsc.js';
import { buildEntityFilter } from '../src/alerts/writer.js';

const NOW = Date.now();
const at = (secondsFromNow) => new Date(NOW + secondsFromNow * 1000).toISOString();

function windowsEvent(type, secondsFromNow, { ip = '198.51.100.23', user = 'analyst', host = 'WIN-01' } = {}) {
  return {
    '@timestamp': at(secondsFromNow),
    'event.type': type,
    'log.source': 'windows',
    'source.ip': ip,
    'user.name': user,
    'host.name': host,
  };
}

function r1Bucket(events, ip = '198.51.100.23') {
  return {
    key: ip,
    doc_count: events.length,
    affected_host: { buckets: [{ key: events[0]?.['host.name'] ?? 'WIN-01' }] },
    affected_user: { buckets: [{ key: events[0]?.['user.name'] ?? 'analyst' }] },
    top_evidence: { hits: { hits: events.map((_source) => ({ _source })) } },
    last_failure: { value_as_string: events.at(-1)?.['@timestamp'] ?? null },
  };
}

test('R1 fires for five canonical auth_failure events from one Windows source IP in 60 seconds', () => {
  const failures = [-55, -45, -35, -25, -15].map((offset) => windowsEvent('auth_failure', offset));
  const candidates = buildCandidatesFromEvents(failures, NOW);

  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].rule_id, 'R1');
  assert.equal(candidates[0].fail_count, 5);
  assert.equal(candidates[0].source_ip, '198.51.100.23');
});

test('R1 does not receive a candidate for four failures', () => {
  const failures = [-55, -45, -35, -25].map((offset) => windowsEvent('auth_failure', offset));
  assert.equal(buildCandidatesFromEvents(failures, NOW).length, 0);
});

test('R2 fires only when canonical auth_success follows the burst from the same IP within five minutes', () => {
  const failures = [-55, -45, -35, -25, -15].map((offset) => windowsEvent('auth_failure', offset));
  const burst = buildR1Candidates([r1Bucket(failures)])[0];
  const success = windowsEvent('auth_success', 30);

  const candidates = buildCandidatesForBurst(burst, [success]);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].rule_id, 'R2');
  assert.equal(candidates[0].evidence.at(-1)['event.type'], 'auth_success');
});

test('R2 rejects a successful authentication from a different IP', () => {
  const failures = [-55, -45, -35, -25, -15].map((offset) => windowsEvent('auth_failure', offset));
  const burst = buildR1Candidates([r1Bucket(failures)])[0];
  const success = windowsEvent('auth_success', 30, { ip: '198.51.100.99' });

  assert.equal(buildCandidatesForBurst(burst, [success]).length, 0);
});

test('R2 rejects an authentication after the five-minute correlation window', () => {
  const failures = [-55, -45, -35, -25, -15].map((offset) => windowsEvent('auth_failure', offset));
  const burst = buildR1Candidates([r1Bucket(failures)])[0];
  const success = windowsEvent('auth_success', 286);

  assert.equal(buildCandidatesForBurst(burst, [success]).length, 0);
});

test('R2 can correlate a qualifying historical 60-second burst to a success near the end of five minutes', () => {
  const failures = [-290, -280, -270, -260, -250].map((offset) => windowsEvent('auth_failure', offset));
  const burst = buildRollingBurstCandidates(failures).at(-1);
  const success = windowsEvent('auth_success', -5);

  assert.ok(burst);
  assert.equal(buildCandidatesForBurst(burst, [success]).length, 1);
});

test('R5 fires when auth_success precedes privilege_assigned for the same user within five minutes', () => {
  const login = windowsEvent('auth_success', -120, { user: 'admin' });
  const privilege = windowsEvent('privilege_assigned', -10, { user: 'admin' });

  const candidate = buildCandidateForPrivilegeEvent(privilege, [login]);
  assert.equal(candidate?.rule_id, 'R5');
  assert.deepEqual(candidate?.evidence, [login, privilege]);
});

test('R5 rejects a login after privilege assignment and a login for another user', () => {
  const privilege = windowsEvent('privilege_assigned', -120, { user: 'admin' });
  const laterLogin = windowsEvent('auth_success', -10, { user: 'admin' });
  const otherUserLogin = windowsEvent('auth_success', -180, { user: 'operator' });

  assert.equal(buildCandidateForPrivilegeEvent(privilege, [laterLogin]), null);
  assert.equal(buildCandidateForPrivilegeEvent(privilege, [otherUserLogin]), null);
});

test('R3 fires at ten distinct ports and does not fire at nine', () => {
  const bucket = (portCount) => ({
    key: '203.0.113.77',
    distinct_ports: { value: portCount },
    affected_host: { buckets: [{ key: '10.0.0.15' }] },
    top_evidence: { hits: { hits: [] } },
  });

  assert.equal(buildR3Candidates([bucket(10)]).length, 1);
  assert.equal(buildR3Candidates([bucket(9)]).length, 0);
});

test('R4 produces a candidate for a matching normalized web attack bucket', () => {
  const event = {
    '@timestamp': at(-10),
    'event.type': 'web_attack',
    'log.source': 'nginx',
    'source.ip': '192.0.2.44',
    'http.uri': '/search?q=<script>alert(1)</script>',
  };
  const bucket = {
    key: event['source.ip'],
    affected_host: { buckets: [{ key: 'web-01' }] },
    top_evidence: { hits: { hits: [{ _source: event }] } },
  };

  assert.equal(buildR4Candidates([bucket]).length, 1);
  assert.equal(buildR4Candidates([bucket])[0].rule_id, 'R4');
});

test('deduplication uses source IP first and host/user only when the IP is absent', () => {
  assert.deepEqual(buildEntityFilter({ source_ip: '198.51.100.23', affected_host: 'WIN-01' }), {
    term: { source_ip: '198.51.100.23' },
  });
  assert.deepEqual(buildEntityFilter({ affected_host: 'WIN-01', affected_user: 'admin' }), {
    bool: { filter: [{ term: { affected_host: 'WIN-01' } }, { term: { affected_user: 'admin' } }] },
  });
  assert.equal(buildEntityFilter({}), null);
});
