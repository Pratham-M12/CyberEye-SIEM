// frontend/src/components/ui/EmptyState.jsx
import React from 'react';
import { IconShieldCheck } from './Icons.jsx';

/**
 * Enterprise SIEM EmptyState component.
 * Displays concise, SOC-appropriate empty state notifications without oversized graphics.
 */
export default function EmptyState({
  icon,
  title = 'No data available',
  description,
  action,
  className = '',
}) {
  const displayIcon = icon || <IconShieldCheck className="h-6 w-6 text-ink-muted" />;

  return (
    <div
      className={`flex flex-col items-center justify-center p-8 text-center ${className}`}
    >
      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full border border-hairline/60 bg-void/60 text-ink-muted shadow-sm">
        {displayIcon}
      </div>
      <h3 className="font-mono text-sm font-semibold tracking-wide text-ink-primary">
        {title}
      </h3>
      {description && (
        <p className="mt-1.5 max-w-md text-xs leading-relaxed text-ink-muted">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
