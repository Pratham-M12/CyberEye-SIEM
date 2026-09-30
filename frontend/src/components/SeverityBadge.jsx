// frontend/src/components/SeverityBadge.jsx

const SEVERITY_STYLES = {
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/40',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/40',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/40',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/40',
};

export default function SeverityBadge({ severity }) {
  const style = SEVERITY_STYLES[severity] || 'bg-ink-dim/15 text-ink-muted border-hairline';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-mono font-semibold uppercase tracking-wider ${style}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity ?? 'unknown'}
    </span>
  );
}
