// backend/src/uploads/service.js
import { randomUUID } from 'crypto';
import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { isIP } from 'net';

import { esClient, LOGS_INDEX } from '../es/client.js';

const WINDOWS_EVENT_ID_MAP = {
  '4624': { type: 'auth_success', severity: 'low' },
  '4625': { type: 'auth_failure', severity: 'medium' },
  '4672': { type: 'privilege_assigned', severity: 'high' },
  '4688': { type: 'process_create', severity: 'low' },
};

const SQLI_XSS_REGEX = /(union\s+select|or\s+1=1|['"]\s*--|<script|javascript:|onerror\s*=|drop\s+table)/i;

const MAX_UPLOAD_SIZE_FALLBACK_MB = 10;
export const MAX_UPLOAD_SIZE_MB = Math.max(
  1,
  parseInt(process.env.MAX_UPLOAD_SIZE_MB || `${MAX_UPLOAD_SIZE_FALLBACK_MB}`, 10) ||
    MAX_UPLOAD_SIZE_FALLBACK_MB
);
export const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024;

export const SUPPORTED_UPLOAD_TYPES = [
  {
    id: 'windows_evtx',
    label: 'Windows EVTX',
    description: 'Parses exported Windows Event Viewer .evtx files into the existing Windows schema.',
    extensions: ['.evtx'],
    encoding: 'base64',
    defaultLogSource: 'windows',
  },
  {
    id: 'syslog',
    label: 'Syslog',
    description: 'Parses Linux syslog and auth log style plaintext files.',
    extensions: ['.log', '.txt'],
    encoding: 'utf8',
    defaultLogSource: 'syslog',
  },
  {
    id: 'apache',
    label: 'Apache Access Log',
    description: 'Parses Apache combined access logs and tags likely web attacks.',
    extensions: ['.log', '.txt'],
    encoding: 'utf8',
    defaultLogSource: 'apache',
  },
  {
    id: 'nginx',
    label: 'Nginx Access Log',
    description: 'Parses Nginx combined access logs and tags likely web attacks.',
    extensions: ['.log', '.txt'],
    encoding: 'utf8',
    defaultLogSource: 'nginx',
  },
  {
    id: 'snort',
    label: 'Snort Alert Log',
    description: 'Parses Snort plaintext alert lines into normalized network intrusion events.',
    extensions: ['.log', '.txt', '.alert'],
    encoding: 'utf8',
    defaultLogSource: 'snort',
  },
  {
    id: 'json',
    label: 'JSON / NDJSON',
    description: 'Parses arrays, single objects, or newline-delimited JSON records.',
    extensions: ['.json', '.ndjson'],
    encoding: 'utf8',
    defaultLogSource: 'json_upload',
  },
  {
    id: 'csv',
    label: 'CSV',
    description: 'Parses CSV files using the header row and maps common SIEM field names.',
    extensions: ['.csv'],
    encoding: 'utf8',
    defaultLogSource: 'csv_upload',
  },
];

const UPLOAD_TYPE_MAP = Object.fromEntries(
  SUPPORTED_UPLOAD_TYPES.map((uploadType) => [uploadType.id, uploadType])
);

export class UploadError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = 'UploadError';
    this.statusCode = statusCode;
  }
}

export function getUploadConfig() {
  return {
    maxUploadSizeMb: MAX_UPLOAD_SIZE_MB,
    maxUploadSizeBytes: MAX_UPLOAD_SIZE_BYTES,
    supportedUploadTypes: SUPPORTED_UPLOAD_TYPES.map(
      ({ id, label, description, extensions, encoding }) => ({
        id,
        label,
        description,
        extensions,
        encoding,
      })
    ),
  };
}

export async function ingestUploadedFile({
  fileName,
  fileSize,
  sourceType,
  encoding,
  content,
}) {
  const uploadType = UPLOAD_TYPE_MAP[sourceType];
  if (!uploadType) {
    throw new UploadError(400, 'Unsupported upload source type.');
  }

  if (!fileName || typeof fileName !== 'string') {
    throw new UploadError(400, 'fileName is required.');
  }

  const sanitizedFileName = path.basename(fileName).trim();
  if (!sanitizedFileName || sanitizedFileName.length > 255 || /[\0\r\n]/.test(sanitizedFileName)) {
    throw new UploadError(400, 'Invalid fileName provided.');
  }

  if (!content || typeof content !== 'string') {
    throw new UploadError(400, 'content is required.');
  }

  if (encoding !== uploadType.encoding) {
    throw new UploadError(
      400,
      `Invalid encoding for ${uploadType.label}. Expected ${uploadType.encoding}.`
    );
  }

  validateFileExtension(sanitizedFileName, uploadType);

  const actualSizeBytes = getActualSizeBytes(content, encoding);
  const declaredSizeBytes =
    Number.isFinite(fileSize) && fileSize > 0 ? Math.trunc(fileSize) : actualSizeBytes;

  if (Math.max(actualSizeBytes, declaredSizeBytes) > MAX_UPLOAD_SIZE_BYTES) {
    throw new UploadError(
      413,
      `File exceeds the ${MAX_UPLOAD_SIZE_MB} MB upload limit.`
    );
  }

  const uploadId = randomUUID();
  const uploadedAt = new Date().toISOString();
  const uploadMeta = {
    uploadId,
    uploadedAt,
    sourceType: uploadType.id,
    fileName: sanitizedFileName,
    fileSize: declaredSizeBytes,
  };

  const parsed = await parseUploadContent({
    content,
    encoding,
    uploadType,
    uploadMeta,
  });

  if (parsed.docs.length === 0) {
    throw new UploadError(
      400,
      'The file did not contain any recognizable events for the selected parser.'
    );
  }

  const operations = parsed.docs.flatMap((doc) => [{ index: { _index: LOGS_INDEX } }, doc]);
  const response = await esClient.bulk({
    refresh: 'wait_for',
    operations,
  });

  const failedItems = response.items.filter((item) => item.index?.error);
  if (failedItems.length === parsed.docs.length) {
    throw new UploadError(
      500,
      failedItems[0]?.index?.error?.reason || 'Elasticsearch rejected every uploaded event.'
    );
  }

  const warnings = [...parsed.warnings];
  if (failedItems.length > 0) {
    warnings.push(
      `${failedItems.length} event(s) were rejected by Elasticsearch. First error: ${
        failedItems[0]?.index?.error?.reason || 'unknown error'
      }`
    );
  }

  return {
    uploadId,
    fileName: sanitizedFileName,
    sourceType: uploadType.id,
    indexedCount: parsed.docs.length - failedItems.length,
    failedCount: failedItems.length,
    skippedCount: parsed.skippedCount,
    warnings,
    logSources: Array.from(new Set(parsed.docs.map((doc) => doc['log.source']).filter(Boolean))),
  };
}

function validateFileExtension(fileName, uploadType) {
  const extension = path.extname(fileName).toLowerCase();
  if (!uploadType.extensions.includes(extension)) {
    throw new UploadError(
      400,
      `${uploadType.label} uploads must use one of: ${uploadType.extensions.join(', ')}.`
    );
  }
}

function getActualSizeBytes(content, encoding) {
  if (encoding === 'base64') {
    return Buffer.from(content, 'base64').length;
  }

  return Buffer.byteLength(content, 'utf8');
}

async function parseUploadContent({ content, encoding, uploadType, uploadMeta }) {
  if (encoding === 'base64') {
    return parseEvtx(Buffer.from(content, 'base64'), uploadMeta);
  }

  const text = stripBom(content);

  switch (uploadType.id) {
    case 'syslog':
      return parseSyslog(text, uploadMeta);
    case 'apache':
    case 'nginx':
      return parseWebAccessLog(text, uploadType.id, uploadMeta);
    case 'snort':
      return parseSnort(text, uploadMeta);
    case 'json':
      return parseJson(text, uploadMeta, uploadType.defaultLogSource);
    case 'csv':
      return parseCsv(text, uploadMeta, uploadType.defaultLogSource);
    default:
      throw new UploadError(400, 'Unsupported upload parser.');
  }
}

function parseSyslog(text, uploadMeta) {
  const lines = splitNonEmptyLines(text);
  const docs = [];
  let skippedCount = 0;

  for (const line of lines) {
    const match = line.match(
      /^(?<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(?<host>\S+)\s(?<program>[^:]+):\s?(?<message>.*)$/
    );

    if (!match?.groups) {
      skippedCount += 1;
      continue;
    }

    const message = match.groups.message || '';
    const classification = classifySyslogMessage(message);
    const userNameMatch = message.match(
      /\bfor (?:invalid user )?(?<user>[A-Za-z0-9._-]+)\b/i
    );

    docs.push(
      buildDocument(
        {
          '@timestamp': parseSyslogTimestamp(match.groups.timestamp) || uploadMeta.uploadedAt,
          'host.name': normalizeKeyword(match.groups.host),
          'user.name': normalizeKeyword(userNameMatch?.groups?.user),
          'source.ip': sanitizeIp(extractFirstIp(message)),
          'event.type': classification.type,
          'event.severity': classification.severity,
          'log.source': 'syslog',
          raw_message: line,
        },
        uploadMeta
      )
    );
  }

  return {
    docs,
    skippedCount,
    warnings: skippedCount > 0 ? [`Skipped ${skippedCount} syslog line(s) that did not match the parser.`] : [],
  };
}

function parseWebAccessLog(text, logSource, uploadMeta) {
  const lines = splitNonEmptyLines(text);
  const docs = [];
  let skippedCount = 0;

  for (const line of lines) {
    const match = line.match(
      /^(?<sourceIp>\S+)\s+\S+\s+\S+\s+\[(?<timestamp>[^\]]+)\]\s+"(?<request>[^"]*)"\s+(?<status>\d{3})\s+\S+/
    );

    if (!match?.groups) {
      skippedCount += 1;
      continue;
    }

    const uri = extractRequestUri(match.groups.request);
    const classification = classifyWebRequest(uri);

    docs.push(
      buildDocument(
        {
          '@timestamp': parseApacheTimestamp(match.groups.timestamp) || uploadMeta.uploadedAt,
          'source.ip': sanitizeIp(match.groups.sourceIp),
          'event.type': classification.type,
          'event.severity': classification.severity,
          'log.source': logSource,
          'http.uri': normalizeKeyword(uri),
          raw_message: line,
        },
        uploadMeta
      )
    );
  }

  return {
    docs,
    skippedCount,
    warnings:
      skippedCount > 0
        ? [`Skipped ${skippedCount} ${logSource} access log line(s) that did not match the parser.`]
        : [],
  };
}

function parseSnort(text, uploadMeta) {
  const lines = splitNonEmptyLines(text);
  const docs = [];
  let skippedCount = 0;

  for (const line of lines) {
    const match =
      line.match(
        /\[Priority:\s*(?<priority>\d+)\].*?\{(?<protocol>\w+)\}\s+(?<sourceIp>[0-9a-fA-F:.]+)(?::(?<sourcePort>\d+))?\s+->\s+(?<destIp>[0-9a-fA-F:.]+)(?::(?<destPort>\d+))?/
      ) ||
      line.match(
        /(?<sourceIp>[0-9a-fA-F:.]+)(?::(?<sourcePort>\d+))?\s+->\s+(?<destIp>[0-9a-fA-F:.]+)(?::(?<destPort>\d+))?/
      );

    if (!match?.groups) {
      skippedCount += 1;
      continue;
    }

    docs.push(
      buildDocument(
        {
          '@timestamp': uploadMeta.uploadedAt,
          'source.ip': sanitizeIp(match.groups.sourceIp),
          'destination.ip': sanitizeIp(match.groups.destIp),
          'destination.port': sanitizePort(match.groups.destPort),
          'event.type': 'network_intrusion',
          'event.severity': mapPriorityToSeverity(match.groups.priority),
          'log.source': 'snort',
          raw_message: line,
        },
        uploadMeta
      )
    );
  }

  return {
    docs,
    skippedCount,
    warnings:
      skippedCount > 0
        ? [`Skipped ${skippedCount} Snort line(s) that did not match the parser.`]
        : [],
  };
}

function parseJson(text, uploadMeta, defaultLogSource) {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new UploadError(400, 'JSON upload is empty.');
  }

  let records;
  const warnings = [];

  try {
    const parsed = JSON.parse(trimmed);
    records = unwrapJsonRecords(parsed);
  } catch (err) {
    const ndjsonLines = splitNonEmptyLines(trimmed);
    records = [];

    for (const line of ndjsonLines) {
      try {
        records.push(JSON.parse(line));
      } catch (lineErr) {
        warnings.push(`Skipped invalid JSON line: ${line.slice(0, 100)}`);
      }
    }
  }

  const docs = [];
  let skippedCount = 0;

  for (const record of records) {
    if (!isPlainObject(record)) {
      skippedCount += 1;
      continue;
    }

    const doc = normalizeStructuredRecord(record, uploadMeta, defaultLogSource);
    if (!doc) {
      skippedCount += 1;
      continue;
    }

    docs.push(doc);
  }

  return {
    docs,
    skippedCount,
    warnings,
  };
}

function parseCsv(text, uploadMeta, defaultLogSource) {
  const rows = parseCsvRows(text);
  if (rows.length < 2) {
    throw new UploadError(400, 'CSV upload must include a header row and at least one event row.');
  }

  const headers = rows[0].map((header) => header.trim());
  const docs = [];
  let skippedCount = 0;

  for (const row of rows.slice(1)) {
    if (row.every((value) => value.trim() === '')) {
      continue;
    }

    const record = {};
    headers.forEach((header, index) => {
      record[header] = row[index] ?? '';
    });

    const doc = normalizeStructuredRecord(record, uploadMeta, defaultLogSource);
    if (!doc) {
      skippedCount += 1;
      continue;
    }

    docs.push(doc);
  }

  return {
    docs,
    skippedCount,
    warnings: [],
  };
}

async function parseEvtx(buffer, uploadMeta) {
  if (process.platform !== 'win32') {
    throw new UploadError(
      400,
      'EVTX parsing requires the backend to run on Windows because it uses Get-WinEvent.'
    );
  }

  const tempPath = path.join(os.tmpdir(), `siem-upload-${uploadMeta.uploadId}.evtx`);
  await fs.writeFile(tempPath, buffer);

  try {
    const records = await readEvtxWithPowerShell(tempPath);
    const docs = [];

    for (const record of records) {
      const eventId = `${record.Id ?? ''}`.trim();
      const userName =
        record.EventData?.TargetUserName ||
        record.EventData?.SubjectUserName ||
        record.EventData?.AccountName ||
        null;

      docs.push(
        buildDocument(
          {
            '@timestamp': coerceTimestamp(record.TimeCreated) || uploadMeta.uploadedAt,
            'source.ip': sanitizeIp(record.EventData?.IpAddress),
            'event.id': normalizeKeyword(eventId),
            'event.type': WINDOWS_EVENT_ID_MAP[eventId]?.type || 'windows_event',
            'event.severity': WINDOWS_EVENT_ID_MAP[eventId]?.severity || 'low',
            'host.name': normalizeKeyword(record.MachineName),
            'user.name': normalizeKeyword(userName),
            'log.source': 'windows',
            raw_message: record.Message || `Windows Event ID ${eventId}`,
          },
          uploadMeta
        )
      );
    }

    return {
      docs,
      skippedCount: 0,
      warnings: [],
    };
  } catch (err) {
    if (err instanceof UploadError) {
      throw err;
    }

    throw new UploadError(400, err.message || 'Failed to parse EVTX file.');
  } finally {
    await fs.unlink(tempPath).catch(() => {});
  }
}

async function readEvtxWithPowerShell(filePath) {
  const script = `
$path = $env:SIEM_EVTX_PATH
$events = Get-WinEvent -Path $path -ErrorAction Stop | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $eventData = @{}
  foreach ($data in $xml.Event.EventData.Data) {
    if ($data.Name) {
      $eventData[$data.Name] = [string]$data.'#text'
    }
  }

  [pscustomobject]@{
    TimeCreated = if ($_.TimeCreated) { $_.TimeCreated.ToString('o') } else { $null }
    Id = [string]$_.Id
    MachineName = $_.MachineName
    Message = $_.Message
    EventData = $eventData
  }
}

$events | ConvertTo-Json -Depth 6 -Compress
`;

  const { stdout, stderr, exitCode } = await spawnAndCollect(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    {
      env: {
        ...process.env,
        SIEM_EVTX_PATH: filePath,
      },
    }
  );

  if (exitCode !== 0) {
    throw new UploadError(
      400,
      stderr.trim() || 'PowerShell failed while reading the EVTX file.'
    );
  }

  if (!stdout.trim()) {
    return [];
  }

  const parsed = JSON.parse(stdout);
  if (Array.isArray(parsed)) {
    return parsed;
  }

  return parsed ? [parsed] : [];
}

function spawnAndCollect(command, args, options = {}, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill();
        reject(new UploadError(500, 'Process execution timed out.'));
      }
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(err);
      }
    });

    child.on('close', (exitCode) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode });
      }
    });
  });
}

function normalizeStructuredRecord(record, uploadMeta, defaultLogSource) {
  const rawMessage =
    stringifyIfObject(readField(record, ['raw_message', 'message', 'raw', 'event.original'])) ||
    JSON.stringify(record);
  const eventId = normalizeKeyword(
    readField(record, ['event.id', 'event_id', 'eventId', 'Id', 'id'])
  );
  const httpUri = normalizeKeyword(
    readField(record, ['http.uri', 'http_uri', 'uri', 'url', 'path', 'request_uri'])
  );
  const logSource = inferLogSource({
    record,
    eventId,
    httpUri,
    rawMessage,
    defaultLogSource,
  });

  const explicitSeverity = normalizeSeverity(
    readField(record, ['event.severity', 'event_severity', 'severity', 'level'])
  );
  const explicitEventType = normalizeEventType(
    readField(record, ['event.type', 'event_type', 'type'])
  );
  const inferred = inferClassification({
    logSource,
    eventId,
    httpUri,
    rawMessage,
  });

  return buildDocument(
    {
      '@timestamp':
        coerceTimestamp(
          readField(record, [
            '@timestamp',
            'timestamp',
            'time',
            'date',
            'TimeCreated',
            'event.created',
          ])
        ) || uploadMeta.uploadedAt,
      'source.ip': sanitizeIp(
        readField(record, [
          'source.ip',
          'source_ip',
          'src_ip',
          'srcIp',
          'client_ip',
          'ip',
        ])
      ),
      'destination.ip': sanitizeIp(
        readField(record, ['destination.ip', 'destination_ip', 'dst_ip', 'dest_ip'])
      ),
      'destination.port': sanitizePort(
        readField(record, ['destination.port', 'destination_port', 'dst_port', 'dest_port', 'port'])
      ),
      'event.id': eventId,
      'event.type': explicitEventType || inferred.type,
      'event.severity': explicitSeverity || inferred.severity,
      'host.name': normalizeKeyword(
        readField(record, ['host.name', 'host', 'hostname', 'computer', 'machineName'])
      ),
      'user.name': normalizeKeyword(
        readField(record, ['user.name', 'username', 'user', 'account', 'TargetUserName'])
      ),
      'log.source': logSource,
      'http.uri': httpUri,
      raw_message: rawMessage,
    },
    uploadMeta
  );
}

function inferLogSource({ record, eventId, httpUri, rawMessage, defaultLogSource }) {
  const explicit = normalizeLogSource(
    readField(record, ['log.source', 'log_source', 'source_type', 'sourceType', 'event.module'])
  );
  if (explicit) {
    return explicit;
  }

  if (eventId && WINDOWS_EVENT_ID_MAP[eventId]) {
    return 'windows';
  }

  if (httpUri && SQLI_XSS_REGEX.test(httpUri)) {
    return 'nginx';
  }

  if (/\[Priority:\s*\d+\]/i.test(rawMessage) || /\s->\s/.test(rawMessage)) {
    return 'snort';
  }

  return defaultLogSource;
}

function inferClassification({ logSource, eventId, httpUri, rawMessage }) {
  if (eventId && WINDOWS_EVENT_ID_MAP[eventId]) {
    return WINDOWS_EVENT_ID_MAP[eventId];
  }

  if (logSource === 'snort') {
    return { type: 'network_intrusion', severity: 'high' };
  }

  if (logSource === 'apache' || logSource === 'nginx') {
    return classifyWebRequest(httpUri || rawMessage);
  }

  if (logSource === 'syslog') {
    return classifySyslogMessage(rawMessage);
  }

  if (logSource === 'json_upload') {
    return { type: 'json_event', severity: 'low' };
  }

  if (logSource === 'csv_upload') {
    return { type: 'csv_event', severity: 'low' };
  }

  return { type: 'system_event', severity: 'low' };
}

function classifySyslogMessage(message) {
  if (/failed password|authentication failure|invalid user/i.test(message)) {
    return { type: 'auth_failure', severity: 'medium' };
  }

  if (/accepted password|session opened|authentication succeeded/i.test(message)) {
    return { type: 'auth_success', severity: 'low' };
  }

  if (/sudo|privilege|root/i.test(message)) {
    return { type: 'privilege_assigned', severity: 'high' };
  }

  return { type: 'system_event', severity: 'low' };
}

function classifyWebRequest(uri) {
  if (uri && SQLI_XSS_REGEX.test(uri)) {
    return { type: 'web_attack', severity: 'medium' };
  }

  return { type: 'web_request', severity: 'low' };
}

function buildDocument(doc, uploadMeta) {
  return compactDocument({
    ...doc,
    'upload.id': uploadMeta.uploadId,
    'upload.file_name': uploadMeta.fileName,
    'upload.source_type': uploadMeta.sourceType,
    'upload.method': 'manual_upload',
    'upload.uploaded_at': uploadMeta.uploadedAt,
    'upload.original_size': uploadMeta.fileSize,
  });
}

function compactDocument(doc) {
  return Object.fromEntries(
    Object.entries(doc).filter(([, value]) => value !== null && value !== undefined && value !== '')
  );
}

function splitNonEmptyLines(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean);
}

function unwrapJsonRecords(parsed) {
  if (Array.isArray(parsed)) {
    return parsed;
  }

  if (isPlainObject(parsed)) {
    if (Array.isArray(parsed.records)) return parsed.records;
    if (Array.isArray(parsed.events)) return parsed.events;
    if (Array.isArray(parsed.data)) return parsed.data;
    return [parsed];
  }

  return [];
}

function parseCsvRows(text) {
  const rows = [];
  let current = '';
  let row = [];
  let inQuotes = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const nextChar = text[index + 1];

    if (char === '"') {
      if (inQuotes && nextChar === '"') {
        current += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === ',' && !inQuotes) {
      row.push(current);
      current = '';
      continue;
    }

    if ((char === '\n' || char === '\r') && !inQuotes) {
      row.push(current);
      current = '';

      if (row.some((value) => value.length > 0)) {
        rows.push(row);
      }

      row = [];
      if (char === '\r' && nextChar === '\n') {
        index += 1;
      }
      continue;
    }

    current += char;
  }

  row.push(current);
  if (row.some((value) => value.length > 0)) {
    rows.push(row);
  }

  return rows;
}

function stripBom(value) {
  return value.replace(/^\uFEFF/, '');
}

function readField(record, candidates) {
  for (const candidate of candidates) {
    if (Object.prototype.hasOwnProperty.call(record, candidate)) {
      return record[candidate];
    }

    const nested = candidate.split('.').reduce((value, key) => {
      if (value && typeof value === 'object' && key in value) {
        return value[key];
      }
      return undefined;
    }, record);

    if (nested !== undefined) {
      return nested;
    }
  }

  return undefined;
}

function normalizeKeyword(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const normalized = `${value}`.trim();
  return normalized || null;
}

function normalizeEventType(value) {
  const normalized = normalizeKeyword(value);
  return normalized ? normalized.toLowerCase().replace(/\s+/g, '_') : null;
}

function normalizeSeverity(value) {
  if (value === null || value === undefined || value === '') {
    return null;
  }

  const normalized = `${value}`.trim().toLowerCase();
  if (!normalized) return null;

  if (['critical', 'high', 'medium', 'low'].includes(normalized)) {
    return normalized;
  }

  if (['1', 'alert', 'fatal', 'emergency'].includes(normalized)) {
    return 'critical';
  }

  if (['2', '3', 'error'].includes(normalized)) {
    return 'high';
  }

  if (['4', '5', 'warning', 'warn'].includes(normalized)) {
    return 'medium';
  }

  if (['6', '7', 'info', 'informational', 'notice', 'debug'].includes(normalized)) {
    return 'low';
  }

  return null;
}

function normalizeLogSource(value) {
  const normalized = normalizeKeyword(value)?.toLowerCase();
  if (!normalized) return null;

  const aliasMap = {
    windows: 'windows',
    winlog: 'windows',
    evtx: 'windows',
    syslog: 'syslog',
    linux: 'syslog',
    apache: 'apache',
    nginx: 'nginx',
    snort: 'snort',
    json_upload: 'json_upload',
    csv_upload: 'csv_upload',
  };

  return aliasMap[normalized] || null;
}

function sanitizeIp(value) {
  const normalized = normalizeKeyword(value);
  return normalized && isIP(normalized) ? normalized : null;
}

function sanitizePort(value) {
  if (value === null || value === undefined || value === '') {
    return null;
  }

  const parsed = parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 65535) {
    return null;
  }

  return parsed;
}

function coerceTimestamp(value) {
  if (!value) return null;

  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function parseSyslogTimestamp(value) {
  const match = `${value}`.match(
    /^(?<month>[A-Z][a-z]{2})\s+(?<day>\d{1,2})\s(?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2})$/
  );

  if (!match?.groups) {
    return null;
  }

  const monthIndex = monthToIndex(match.groups.month);
  if (monthIndex === null) {
    return null;
  }

  const now = new Date();
  const parsed = new Date(
    now.getFullYear(),
    monthIndex,
    parseInt(match.groups.day, 10),
    parseInt(match.groups.hour, 10),
    parseInt(match.groups.minute, 10),
    parseInt(match.groups.second, 10)
  );

  return parsed.toISOString();
}

function parseApacheTimestamp(value) {
  const match = `${value}`.match(
    /^(?<day>\d{2})\/(?<month>[A-Z][a-z]{2})\/(?<year>\d{4}):(?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2})\s(?<offset>[+-]\d{4})$/
  );

  if (!match?.groups) {
    return null;
  }

  const monthIndex = monthToIndex(match.groups.month);
  if (monthIndex === null) {
    return null;
  }

  const isoLike = `${match.groups.year}-${String(monthIndex + 1).padStart(2, '0')}-${match.groups.day}T${match.groups.hour}:${match.groups.minute}:${match.groups.second}${match.groups.offset.slice(0, 3)}:${match.groups.offset.slice(3)}`;
  return coerceTimestamp(isoLike);
}

function monthToIndex(month) {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const index = months.indexOf(month);
  return index === -1 ? null : index;
}

function extractRequestUri(requestLine) {
  const parts = `${requestLine || ''}`.split(' ');
  return parts.length >= 2 ? parts[1] : null;
}

function extractFirstIp(value) {
  return `${value || ''}`.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] || null;
}

function mapPriorityToSeverity(priority) {
  switch (`${priority || ''}`) {
    case '1':
      return 'critical';
    case '2':
      return 'high';
    case '3':
      return 'medium';
    default:
      return 'low';
  }
}

function stringifyIfObject(value) {
  if (value && typeof value === 'object') {
    return JSON.stringify(value);
  }

  return normalizeKeyword(value);
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
