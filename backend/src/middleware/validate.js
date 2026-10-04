// backend/src/middleware/validate.js
import { isIP } from 'net';

export const ALLOWED_SEVERITIES = Object.freeze(['low', 'medium', 'high', 'critical']);
export const ALLOWED_STATUSES = Object.freeze(['open', 'acknowledged', 'closed']);
export const MAX_ES_WINDOW = 10000;

const ID_REGEX = /^[a-zA-Z0-9_-]{1,128}$/;
const TIME_WINDOW_REGEX = /^([1-9]\d{0,3})([smhdw])$/;
const INTERVAL_REGEX = /^([1-9]\d{0,3})([smhdw])$/;

/**
 * Validates document or entity ID (safe characters, reasonable length).
 */
export function isValidId(id) {
  return typeof id === 'string' && ID_REGEX.test(id);
}

/**
 * Validates IPv4 or IPv6 address.
 */
export function isValidIp(ip) {
  if (typeof ip !== 'string' || ip.length > 45) return false;
  return isIP(ip) !== 0;
}

/**
 * Validates severity against the canonical SIEM severity levels.
 */
export function isValidSeverity(severity) {
  return typeof severity === 'string' && ALLOWED_SEVERITIES.includes(severity.toLowerCase());
}

/**
 * Validates alert workflow status.
 */
export function isValidStatus(status) {
  return typeof status === 'string' && ALLOWED_STATUSES.includes(status.toLowerCase());
}

/**
 * Validates time window format (e.g., '30s', '5m', '24h', '7d').
 */
export function isValidTimeWindow(window) {
  if (typeof window !== 'string') return false;
  const match = window.match(TIME_WINDOW_REGEX);
  if (!match) return false;
  const val = parseInt(match[1], 10);
  const unit = match[2];
  if (unit === 'd' && val > 365) return false;
  if (unit === 'w' && val > 52) return false;
  return true;
}

/**
 * Validates aggregation interval format (e.g., '1m', '1h', '1d').
 */
export function isValidInterval(interval) {
  if (typeof interval !== 'string') return false;
  return INTERVAL_REGEX.test(interval);
}

/**
 * Validates an ISO 8601 or standard date string.
 */
export function isValidDateString(dateStr) {
  if (typeof dateStr !== 'string' || dateStr.length > 50) return false;
  const timestamp = Date.parse(dateStr);
  return Number.isFinite(timestamp);
}

/**
 * Sanitizes and bounds free-text search queries.
 */
export function sanitizeSearchQuery(q, maxLength = 200) {
  if (typeof q !== 'string') return '';
  return q.slice(0, maxLength).replace(/[\x00-\x1f\x7f]/g, '').trim();
}

/**
 * Validates pagination inputs and checks against Elasticsearch's max_result_window limit.
 */
export function validatePagination(pageStr, pageSizeStr, maxWindow = MAX_ES_WINDOW) {
  const page = parseInt(pageStr, 10);
  const pageSize = parseInt(pageSizeStr, 10);

  if (Number.isNaN(page) || page < 1 || page > 10000) {
    return { valid: false, error: 'Parameter "page" must be a positive integer between 1 and 10,000' };
  }

  if (Number.isNaN(pageSize) || pageSize < 1 || pageSize > 200) {
    return { valid: false, error: 'Parameter "pageSize" must be a positive integer between 1 and 200' };
  }

  const from = (page - 1) * pageSize;
  if (from + pageSize > maxWindow) {
    return {
      valid: false,
      error: `Pagination window (page * pageSize) exceeds maximum allowed limit of ${maxWindow}`,
    };
  }

  return { valid: true, page, pageSize, pageNum: page, size: pageSize, from };
}
