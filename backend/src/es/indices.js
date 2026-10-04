import { esClient, LOGS_INDEX, ALERTS_INDEX, USERS_INDEX } from './client.js';

// Mapping for the normalized event index. Every log source (Winlogbeat, Snort
// via Filebeat, Apache/Nginx via Filebeat, syslog) is written here in the
// common schema defined in the project master prompt.
const logsMapping = {
  mappings: {
    properties: {
      '@timestamp': { type: 'date' },
      'source.ip': { type: 'ip' },
      'destination.ip': { type: 'ip' },
      'destination.port': { type: 'integer' },
      'event.type': { type: 'keyword' },
      'event.severity': { type: 'keyword' },
      'event.id': { type: 'keyword' }, // e.g. Windows Event ID: 4624, 4625, 4672, 4688
      'host.name': { type: 'keyword' },
      'user.name': { type: 'keyword' },
      'log.source': { type: 'keyword' }, // windows | snort | nginx | apache | syslog
      'http.uri': { type: 'keyword' },
      'upload.id': { type: 'keyword' },
      'upload.file_name': { type: 'keyword' },
      'upload.source_type': { type: 'keyword' },
      'upload.method': { type: 'keyword' },
      'upload.uploaded_at': { type: 'date' },
      'upload.original_size': { type: 'integer' },
      'threat.score': { type: 'integer' },
      'threat.is_malicious': { type: 'boolean' },
      raw_message: { type: 'text' },
    },
  },
  settings: {
    number_of_shards: 1,
    number_of_replicas: 0,
  },
};

// Mapping for fired detection-rule alerts.
const alertsMapping = {
  mappings: {
    properties: {
      '@timestamp': { type: 'date' },
      rule_id: { type: 'keyword' },
      rule_name: { type: 'keyword' },
      severity: { type: 'keyword' },
      affected_host: { type: 'keyword' },
      affected_user: { type: 'keyword' },
      source_ip: { type: 'ip' },
      status: { type: 'keyword' }, // open | acknowledged | closed
      evidence: { type: 'object', enabled: true },
      mitre_technique_id: { type: 'keyword' },
      mitre_technique_name: { type: 'keyword' },
      mitre_tactic: { type: 'keyword' },
      llm_summary: { type: 'text' },
    },
  },
};

// Mapping for user accounts in Phase 7C RBAC.
const usersMapping = {
  mappings: {
    properties: {
      username: { type: 'keyword' },
      passwordHash: { type: 'keyword', index: false },
      salt: { type: 'keyword', index: false },
      role: { type: 'keyword' }, // admin | analyst | read_only
      createdAt: { type: 'date' },
      updatedAt: { type: 'date' },
      isActive: { type: 'boolean' },
      lastLoginAt: { type: 'date' },
    },
  },
  settings: {
    number_of_shards: 1,
    number_of_replicas: 0,
  },
};

export async function ensureIndices() {
  await ensureIndex(LOGS_INDEX, logsMapping);
  await ensureIndex(ALERTS_INDEX, alertsMapping);
  await ensureIndex(USERS_INDEX, usersMapping);
}

async function ensureIndex(name, body) {
  const exists = await esClient.indices.exists({ index: name });
  if (exists) {
    await esClient.indices.putMapping({
      index: name,
      properties: body.mappings.properties,
    });
    console.log(`[es] index "${name}" already exists, synced mapping`);
    return;
  }
  await esClient.indices.create({ index: name, ...body });
  console.log(`[es] created index "${name}"`);
}
