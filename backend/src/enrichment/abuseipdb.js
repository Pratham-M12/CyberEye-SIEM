import axios from 'axios';
import 'dotenv/config';
import { esClient, LOGS_INDEX } from '../es/client.js';

const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY; // API required here
const ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check';
const MALICIOUS_SCORE_THRESHOLD = 50;

/**
 * Cross-checks a source IP against AbuseIPDB and returns
 * { score, isMalicious }. Returns null if no API key is configured, so
 * enrichIngestedEvent() can skip cleanly during local dev.
 */
export async function checkIp(ip) {
  if (!ABUSEIPDB_API_KEY || ABUSEIPDB_API_KEY === 'API required here') {
    console.warn('[abuseipdb] ABUSEIPDB_API_KEY not configured — skipping enrichment');
    return null;
  }

  const res = await axios.get(ABUSEIPDB_URL, {
    params: { ipAddress: ip, maxAgeInDays: 90 },
    headers: { Key: ABUSEIPDB_API_KEY, Accept: 'application/json' },
  });

  const score = res.data?.data?.abuseConfidenceScore ?? 0;
  return { score, isMalicious: score >= MALICIOUS_SCORE_THRESHOLD };
}

/**
 * Enriches a single already-indexed log event with threat.score /
 * threat.is_malicious fields, looked up from AbuseIPDB for that event's
 * source.ip. Called from the ingest API route right after a document lands
 * in siem-logs.
 */
export async function enrichIngestedEvent(docId, sourceIp) {
  if (!sourceIp) return;

  const result = await checkIp(sourceIp);
  if (!result) return;

  await esClient.update({
    index: LOGS_INDEX,
    id: docId,
    doc: {
      threat: { score: result.score, is_malicious: result.isMalicious },
    },
  });
}
