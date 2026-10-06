import React from 'react';

export default function PanelHeader({
  icon,
  title,
  subtitle,
  right,
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-hairline bg-raised px-4 sm:px-5 py-3 sm:py-4">
      <div className="flex items-center gap-2.5 sm:gap-3 min-w-0">
        {icon && (
          <div className="flex h-9 w-9 sm:h-10 sm:w-10 shrink-0 items-center justify-center rounded-panel bg-accent text-white shadow [&>svg]:h-4 sm:[&>svg]:h-5 [&>svg]:w-4 sm:[&>svg]:w-5">
            {icon}
          </div>
        )}
        <div className="min-w-0">
          <h2 className="font-mono text-sm sm:text-base font-semibold tracking-wide text-white truncate">
            {title}
          </h2>
          {subtitle && (
            <p className="mt-0.5 text-xs text-ink-muted truncate">
              {subtitle}
            </p>
          )}
        </div>
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}