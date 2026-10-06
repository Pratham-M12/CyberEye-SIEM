// frontend/src/components/DashboardControls.jsx
import React from 'react';
import { TIME_RANGES } from '../constants/timeRange.js';

/**
 * Enterprise SIEM Global Dashboard Controls Component.
 * Provides global time-range selection, auto-refresh toggling (30s),
 * manual refresh trigger with in-flight visual indication, and last-updated display.
 */
export default function DashboardControls({
  timeRange,
  onTimeRangeChange,
  autoRefresh,
  onToggleAutoRefresh,
  onManualRefresh,
  isRefreshing,
  lastUpdated,
  hasError = false,
  onClearError,
}) {
  return (
    <nav
      aria-label="Dashboard controls"
      className="border-b border-hairline/80 bg-panel/60 backdrop-blur-sm"
    >
      <div className="mx-auto flex max-w-[1700px] flex-wrap items-center justify-between gap-3 px-4 sm:px-8 py-2 sm:py-2.5">
        {/* Left: Global Time-Range Selector */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 font-mono text-xs text-ink-muted mr-1">
            <svg
              className="h-3.5 w-3.5 text-accent"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth="2"
              aria-hidden="true"
            >
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            <span className="font-semibold uppercase tracking-wider text-[11px] text-ink-dim">
              Time Range:
            </span>
          </div>

          <div
            role="group"
            aria-label="Time range selector"
            className="flex items-center gap-1 rounded-lg border border-hairline/80 bg-raised/80 p-0.5 shadow-sm"
          >
            {TIME_RANGES.map((range) => {
              const isActive = timeRange === range.id;
              return (
                <button
                  key={range.id}
                  type="button"
                  onClick={() => onTimeRangeChange(range.id)}
                  aria-pressed={isActive}
                  title={range.fullLabel}
                  className={`rounded-md px-3 py-1.5 sm:py-1 min-h-[32px] sm:min-h-0 font-mono text-xs transition-all ${
                    isActive
                      ? 'bg-accent font-semibold text-white shadow-sm'
                      : 'text-ink-secondary hover:bg-white/5 hover:text-white'
                  }`}
                >
                  {range.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Right: Auto-Refresh, Manual Refresh, Last Updated & Status */}
        <div className="flex flex-wrap items-center gap-2.5 sm:gap-3">
          {/* Non-destructive background error indicator */}
          {hasError && (
            <div
              role="alert"
              className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-2.5 py-1 text-xs text-severity-high"
            >
              <span className="text-xs">⚠️</span>
              <span className="font-medium text-[11px] hidden sm:inline">
                Sync failed. Showing cached data.
              </span>
              <span className="font-medium text-[11px] sm:hidden">
                Sync error
              </span>
              {onClearError && (
                <button
                  type="button"
                  onClick={onClearError}
                  aria-label="Dismiss error notification"
                  className="ml-1 text-severity-high hover:text-white transition"
                >
                  ✕
                </button>
              )}
            </div>
          )}

          {/* Auto-Refresh Toggle */}
          <button
            type="button"
            onClick={onToggleAutoRefresh}
            aria-pressed={autoRefresh}
            title={
              autoRefresh
                ? 'Auto-refresh active (every 30s). Click to pause.'
                : 'Auto-refresh paused. Click to enable 30s polling.'
            }
            className={`flex items-center gap-2 rounded-lg border px-3 py-2 sm:py-1.5 min-h-[36px] text-xs font-medium transition ${
              autoRefresh
                ? 'border-emerald-700/50 bg-emerald-950/30 text-emerald-300 hover:bg-emerald-950/50'
                : 'border-hairline bg-raised/80 text-ink-muted hover:bg-white/5 hover:text-ink-secondary'
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full transition-all ${
                autoRefresh ? 'bg-emerald-400 animate-pulse' : 'bg-ink-dim'
              }`}
            />
            <span className="font-mono text-[11px]">
              Auto-refresh: {autoRefresh ? '30s' : 'Off'}
            </span>
          </button>

          {/* Manual Refresh Action */}
          <button
            type="button"
            onClick={onManualRefresh}
            disabled={isRefreshing}
            aria-label="Manually refresh all dashboard telemetry"
            title="Refresh all panels"
            className="flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/15 px-3 py-2 sm:py-1.5 min-h-[36px] font-mono text-xs font-semibold text-accent transition hover:bg-accent hover:text-white disabled:opacity-60 disabled:cursor-not-allowed shadow-sm"
          >
            <svg
              className={`h-3.5 w-3.5 shrink-0 ${
                isRefreshing ? 'animate-spin' : ''
              }`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth="2.5"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              />
            </svg>
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>

          {/* Last Updated Timestamp */}
          <div className="flex items-center gap-1.5 font-mono text-[11px] text-ink-muted tabular pl-1 border-l border-hairline/60">
            <span className="text-ink-dim hidden md:inline">Updated:</span>
            <span>
              {lastUpdated
                ? lastUpdated.toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  })
                : '—'}
            </span>
          </div>
        </div>
      </div>
    </nav>
  );
}
