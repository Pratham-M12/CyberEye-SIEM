// frontend/src/components/ui/LoadingSkeleton.jsx
import React from 'react';

/**
 * Enterprise SIEM LoadingSkeleton component.
 * Provides unified, accessible pulsating skeleton placeholders for:
 * - text / blocks (default)
 * - metric cards ('metric')
 * - alert queue items ('alert-list')
 * - area charts ('chart')
 * - horizontal bar charts ('bar-chart')
 * - tabular logs ('table')
 * - alert detail drawer ('drawer')
 */
export default function LoadingSkeleton({
  variant = 'text',
  count = 5,
  height = 'h-4',
  width = 'w-full',
  className = '',
}) {
  if (variant === 'metric') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label="Loading metric value"
        className={`animate-pulse space-y-2 ${className}`}
      >
        <div className="h-7 w-16 rounded bg-hairline/60" />
        <div className="h-2.5 w-20 rounded bg-hairline/30" />
      </div>
    );
  }

  if (variant === 'alert-list') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label="Loading alerts queue"
        className={`divide-y divide-hairline/30 animate-pulse ${className}`}
      >
        {Array.from({ length: count }).map((_, index) => (
          <div
            key={index}
            className="border-b border-l-4 border-hairline/30 border-l-hairline/40 px-4 py-3 bg-panel/30"
          >
            <div className="flex items-center justify-between gap-3">
              <div className="h-4 w-40 rounded bg-hairline/50" />
              <div className="h-4 w-16 rounded-full bg-hairline/40" />
            </div>
            <div className="mt-2.5 flex items-center justify-between gap-2">
              <div className="h-3 w-28 rounded bg-hairline/30" />
              <div className="h-3 w-14 rounded bg-hairline/30" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (variant === 'chart') {
    const heights = [45, 65, 30, 80, 55, 70, 40, 90, 60, 75, 48, 85];
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label="Loading timeline chart"
        className={`flex h-[320px] w-full flex-col justify-between rounded-lg border border-hairline/40 bg-void/40 p-4 animate-pulse ${className}`}
      >
        <div className="flex flex-1 items-end justify-between gap-2 px-2 pb-4 pt-6">
          {heights.map((h, i) => (
            <div key={i} className="flex h-full flex-1 flex-col justify-end items-center">
              <div
                className="w-full rounded-t bg-hairline/30"
                style={{ height: `${h}%` }}
              />
            </div>
          ))}
        </div>
        <div className="flex justify-between border-t border-hairline/40 px-2 pt-3">
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-2.5 w-12 rounded bg-hairline/30" />
          ))}
        </div>
      </div>
    );
  }

  if (variant === 'bar-chart') {
    const barWidths = [85, 60, 95, 45, 70, 35, 50, 80];
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label="Loading top attackers chart"
        className={`flex h-[320px] w-full flex-col justify-around rounded-lg border border-hairline/40 bg-void/40 p-4 animate-pulse ${className}`}
      >
        {barWidths.slice(0, count).map((w, i) => (
          <div key={i} className="flex items-center gap-3">
            <div className="h-3.5 w-24 shrink-0 rounded bg-hairline/40 font-mono" />
            <div
              className="h-5 rounded-r bg-hairline/30"
              style={{ width: `${w}%` }}
            />
            <div className="h-3 w-6 shrink-0 rounded bg-hairline/20" />
          </div>
        ))}
      </div>
    );
  }

  if (variant === 'table') {
    return (
      <>
        {Array.from({ length: count }).map((_, rowIndex) => (
          <tr
            key={rowIndex}
            className="animate-pulse border-b border-hairline/30 odd:bg-panel/40 even:bg-raised/30"
          >
            <td className="px-5 py-3.5">
              <div className="h-3.5 w-28 rounded bg-hairline/40" />
            </td>
            <td className="px-5 py-3.5">
              <div className="h-4 w-16 rounded-full bg-hairline/40" />
            </td>
            <td className="px-5 py-3.5">
              <div className="h-3.5 w-16 rounded bg-hairline/40" />
            </td>
            <td className="px-5 py-3.5">
              <div className="h-3.5 w-24 rounded bg-hairline/40" />
            </td>
            <td className="px-5 py-3.5">
              <div className="h-3.5 w-24 rounded bg-hairline/40" />
            </td>
            <td className="px-5 py-3.5">
              <div className="h-3.5 w-20 rounded bg-hairline/40" />
            </td>
            <td className="px-5 py-3.5">
              <div className="h-3.5 w-16 rounded bg-hairline/40" />
            </td>
          </tr>
        ))}
      </>
    );
  }

  if (variant === 'drawer') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label="Loading alert details"
        className={`animate-pulse space-y-6 p-5 ${className}`}
      >
        <div className="border-b border-hairline pb-5">
          <div className="flex items-center gap-2">
            <div className="h-5 w-20 rounded-full bg-hairline/50" />
            <div className="h-3.5 w-12 rounded bg-hairline/30" />
          </div>
          <div className="mt-3 h-6 w-56 rounded bg-hairline/60" />
          <div className="mt-2 h-3.5 w-36 rounded bg-hairline/30" />
        </div>

        <div>
          <div className="h-3 w-28 rounded bg-hairline/40" />
          <div className="mt-2 h-12 w-full rounded bg-hairline/25" />
        </div>

        <div className="grid grid-cols-2 gap-3">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="rounded-md border border-hairline/40 bg-void/50 p-3">
              <div className="h-2.5 w-20 rounded bg-hairline/40" />
              <div className="mt-2 h-4 w-32 rounded bg-hairline/50" />
            </div>
          ))}
        </div>

        <div>
          <div className="h-3 w-32 rounded bg-hairline/40" />
          <div className="mt-2 h-20 w-full rounded-md border border-hairline/40 bg-void/50" />
        </div>

        <div>
          <div className="h-3 w-44 rounded bg-hairline/40" />
          <div className="mt-2 space-y-2">
            {[0, 1].map((i) => (
              <div key={i} className="h-16 w-full rounded-md border border-hairline/40 bg-void/50" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div
      role="status"
      aria-busy="true"
      className={`${height} ${width} animate-pulse rounded bg-hairline/40 ${className}`}
    />
  );
}