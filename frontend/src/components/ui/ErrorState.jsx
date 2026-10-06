// frontend/src/components/ui/ErrorState.jsx
import React from 'react';

/**
 * Enterprise SIEM ErrorState component.
 * Displays safe, human-readable API and connection error alerts with optional retry action.
 * Never exposes raw error objects, stack traces, or internal server paths.
 */
export default function ErrorState({
  title = 'Unable to load data',
  message = 'The SIEM API is temporarily unavailable.',
  onRetry,
  compact = false,
  className = '',
}) {
  if (compact) {
    return (
      <div
        role="alert"
        aria-live="polite"
        className={`flex items-center justify-between gap-3 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-2.5 text-xs text-severity-high ${className}`}
      >
        <div className="flex items-center gap-2 min-w-0">
          <span className="shrink-0 text-sm">⚠️</span>
          <span className="truncate font-medium">{message || title}</span>
        </div>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="shrink-0 font-mono font-semibold underline underline-offset-2 hover:text-white transition"
          >
            Try again
          </button>
        )}
      </div>
    );
  }

  return (
    <div
      role="alert"
      aria-live="polite"
      className={`flex flex-col items-center justify-center p-8 text-center ${className}`}
    >
      <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-full border border-severity-high/30 bg-severity-high/10 text-xl text-severity-high">
        ⚠️
      </div>
      <h3 className="font-mono text-sm font-semibold tracking-wide text-ink-primary">
        {title}
      </h3>
      {message && (
        <p className="mt-1.5 max-w-sm text-xs leading-relaxed text-ink-muted">
          {message}
        </p>
      )}
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-hairline bg-raised px-3.5 py-1.5 font-mono text-xs font-medium text-ink-primary transition hover:border-accent hover:text-accent"
        >
          <span>↻</span>
          <span>Try again</span>
        </button>
      )}
    </div>
  );
}
