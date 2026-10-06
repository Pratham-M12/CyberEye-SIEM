// frontend/src/components/SeverityBadge.jsx
import React from 'react';
import {
  IconAlertOctagon,
  IconAlertTriangle,
  IconInfo,
  IconShield,
} from './ui/Icons.jsx';

const SEVERITY_STYLES = {
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/40',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/40',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/40',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/40',
};

function renderSeverityIcon(sev) {
  const key = String(sev).toLowerCase();
  switch (key) {
    case 'critical':
      return <IconAlertOctagon className="h-3 w-3 shrink-0" />;
    case 'high':
      return <IconAlertTriangle className="h-3 w-3 shrink-0" />;
    case 'medium':
      return <IconInfo className="h-3 w-3 shrink-0" />;
    case 'low':
      return <IconShield className="h-3 w-3 shrink-0" />;
    default:
      return <span className="h-1.5 w-1.5 rounded-full bg-current shrink-0" aria-hidden="true" />;
  }
}

export default function SeverityBadge({ severity }) {
  const normalized = severity ? String(severity).toLowerCase() : 'unknown';
  const style = SEVERITY_STYLES[normalized] || 'bg-ink-dim/15 text-ink-muted border-hairline';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-mono font-semibold uppercase tracking-wider ${style}`}
    >
      {renderSeverityIcon(normalized)}
      <span>{severity ?? 'unknown'}</span>
    </span>
  );
}
