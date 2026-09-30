import { esClient, LOGS_INDEX, pingElasticsearch } from './client.js';
import { runAllRules } from '../rules/engine.js';

// Writes a handful of synthetic-but-realistic events, timestamped "now",
// designed to trip every detection rule on the very next 30s rule engine
// tick. Useful for demos/screenshots when real Winlogbeat/Snort/Filebeat
// agents aren't running yet.
//
// Run with `npm run seed` (from backend/) while the backend is up.

const now = () => new Date();
const secondsAgo = (s) => new Date(Date.now() - s * 1000).toISOString();

function bulkDocs(docs) {
  return docs.flatMap((doc) => [{ index: { _index: LOGS_INDEX } }, doc]);
}

function bruteForceAndStuffing() {
  const ip = '198.51.100.23';
  const host = 'WIN-DC01';
  const user = 'jsmith';

  const failures = Array.from({ length: 6 }, (_, i) => ({
    '@timestamp': secondsAgo(10 - i),
    'source.ip': ip,
    'event.type': 'auth_failure',
    'event.severity': 'medium',
    'event.id': '4625',
    'host.name': host,
    'user.name': user,
    'log.source': 'windows',
    raw_message: `An account failed to log on. Account Name: ${user} Source Network Address: ${ip}`,
  }));

  const success = {
    '@timestamp': secondsAgo(2),
    'source.ip': ip,
    'event.type': 'auth_success',
    'event.severity': 'low',
    'event.id': '4624',
    'host.name': host,
    'user.name': user,
    'log.source': 'windows',
    raw_message: `An account was successfully logged on. Account Name: ${user} Source Network Address: ${ip}`,
  };

  return [...failures, success];
}

function portScan() {
  const ip = '203.0.113.77';
  const host = '10.0.0.15';
  const ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389];

  return ports.map((port, i) => ({
    '@timestamp': secondsAgo(11 - i),
    'source.ip': ip,
    'destination.ip': host,
    'destination.port': port,
    'event.type': 'network_intrusion',
    'event.severity': 'high',
    'host.name': host,
    'log.source': 'snort',
    raw_message: `[Snort] Priority: 2 {TCP} ${ip}:${40000 + i} -> ${host}:${port}`,
  }));
}

function webAttack() {
  const ip = '192.0.2.44';
  const host = 'web-01';
  const payloads = [
    "/login.php?user=admin'--",
    '/search?q=<script>alert(1)</script>',
    "/products?id=1 UNION SELECT username,password FROM users",
  ];

  return payloads.map((uri, i) => ({
    '@timestamp': secondsAgo(8 - i * 3),
    'source.ip': ip,
    'event.type': 'web_attack',
    'event.severity': 'medium',
    'host.name': host,
    'log.source': 'nginx',
    'http.uri': uri,
    raw_message: `${ip} - - "GET ${uri} HTTP/1.1" 200 512`,
  }));
}

function privilegeEscalation() {
  const ip = '10.0.0.88';
  const host = 'WIN-SRV02';
  const user = 'contractor01';

  return [
    {
      '@timestamp': secondsAgo(20),
      'source.ip': ip,
      'event.type': 'auth_success',
      'event.severity': 'low',
      'event.id': '4624',
      'host.name': host,
      'user.name': user,
      'log.source': 'windows',
      raw_message: `An account was successfully logged on. Account Name: ${user}`,
    },
    {
      '@timestamp': secondsAgo(5),
      'source.ip': ip,
      'event.type': 'privilege_assigned',
      'event.severity': 'high',
      'event.id': '4672',
      'host.name': host,
      'user.name': user,
      'log.source': 'windows',
      raw_message: `Special privileges assigned to new logon. Account Name: ${user} Privileges: SeDebugPrivilege`,
    },
  ];
}

async function seed() {
  const alive = await pingElasticsearch();
  if (!alive) {
    console.error('[seed] Could not reach Elasticsearch. Is docker-compose up?');
    process.exit(1);
  }

  const docs = [
    ...bruteForceAndStuffing(),
    ...portScan(),
    ...webAttack(),
    ...privilegeEscalation(),
  ];

  const res = await esClient.bulk({ refresh: 'wait_for', operations: bulkDocs(docs) });

  if (res.errors) {
    const failed = res.items.filter((i) => i.index?.error);
    console.error(`[seed] ${failed.length} document(s) failed to index:`, failed[0]?.index?.error);
    process.exit(1);
  }

  const rulesResult = await runAllRules();
  console.log(`[seed] indexed ${docs.length} synthetic events at ${now().toISOString()}.`);
  console.log(`[seed] immediate rule pass created ${rulesResult.totalFired} alert(s).`);
  console.log('[seed] the rule engine runs every 30s — watch the Alert Queue for R1–R5 to fire.');
  process.exit(0);
}

seed().catch((err) => {
  console.error('[seed] failed:', err);
  process.exit(1);
});
