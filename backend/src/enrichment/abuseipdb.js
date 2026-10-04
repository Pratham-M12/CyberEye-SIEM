import axios from 'axios';
import 'dotenv/config';
import { esClient, LOGS_INDEX } from '../es/client.js';

const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY; // API required here
const ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check';
const MALICIOUS_SCORE_THRESHOLD = 50;

/**
 * Cross-checks a source IP against AbuseIPDB and returns
 * { score, isMalicious, totalReports, countryCode, isp, domain, usageType, lastReportedAt }.
 * Returns null if no API key is configured, or on error/timeout, so
 * enrichIngestedEvent() can skip cleanly during local dev or API disruptions.
 */
export async function checkIp(ip) {
  if (!ABUSEIPDB_API_KEY || ABUSEIPDB_API_KEY === 'API required here') {
    console.warn('[abuseipdb] ABUSEIPDB_API_KEY not configured — skipping enrichment');
    return null;
  }

  if (!ip || typeof ip !== 'string') {
    return null;
  }

  try {
    const res = await axios.get(ABUSEIPDB_URL, {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: ABUSEIPDB_API_KEY, Accept: 'application/json' },
      timeout: 5000,
    });

    const data = res.data?.data;
    const score = data?.abuseConfidenceScore ?? 0;
    return {
      score,
      isMalicious: score >= MALICIOUS_SCORE_THRESHOLD,
      totalReports: data?.totalReports ?? 0,
      countryCode: data?.countryCode ?? null,
      isp: data?.isp ?? null,
      domain: data?.domain ?? null,
      usageType: data?.usageType ?? null,
      lastReportedAt: data?.lastReportedAt ?? null,
    };
  } catch (err) {
    const detail =
      err.response?.data?.errors?.[0]?.detail ||
      (err.response?.status ? `HTTP ${err.response.status}` : err.message);
    console.error(`[abuseipdb] check failed for IP "${ip}":`, detail);
    return null;
  }
}

/**
 * Enriches a single already-indexed log event with threat.score /
 * threat.is_malicious fields, looked up from AbuseIPDB for that event's
 * source.ip. Called from the poller or ingest API route right after a document lands
 * in siem-logs.
 */
export async function enrichIngestedEvent(docId, sourceIp) {
  if (!sourceIp || !docId) return;

  try {
    const result = await checkIp(sourceIp);
    if (!result) return;

    await esClient.update({
      index: LOGS_INDEX,
      id: docId,
      doc: {
        threat: { score: result.score, is_malicious: result.isMalicious },
      },
    });
  } catch (err) {
    console.error(`[abuseipdb] enrichment update failed for ${docId}:`, err.message);
  }
}

