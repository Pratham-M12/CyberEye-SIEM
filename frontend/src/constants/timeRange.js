// frontend/src/constants/timeRange.js

export const TIME_RANGES = [
  {
    id: '15m',
    label: '15m',
    fullLabel: 'Last 15 minutes',
    ms: 15 * 60 * 1000,
    interval: '1m',
  },
  {
    id: '1h',
    label: '1h',
    fullLabel: 'Last 1 hour',
    ms: 60 * 60 * 1000,
    interval: '5m',
  },
  {
    id: '6h',
    label: '6h',
    fullLabel: 'Last 6 hours',
    ms: 6 * 60 * 60 * 1000,
    interval: '15m',
  },
  {
    id: '24h',
    label: '24h',
    fullLabel: 'Last 24 hours',
    ms: 24 * 60 * 60 * 1000,
    interval: '1h',
  },
];

export const DEFAULT_TIME_RANGE = '24h';

export function getTimeRange(id) {
  return TIME_RANGES.find((r) => r.id === id) || TIME_RANGES[3];
}
