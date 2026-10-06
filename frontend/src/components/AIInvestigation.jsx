// frontend/src/components/AIInvestigation.jsx
import React from 'react';
import SeverityBadge from './SeverityBadge.jsx';

export default function AIInvestigation({ report }) {
  if (!report) {
    return (
      <div className="rounded-lg border border-hairline/60 bg-void/50 p-4 text-center">
        <p className="font-mono text-xs text-ink-muted">
          No AI investigation generated yet. Analysts can generate an on-demand report above.
        </p>
      </div>
    );
  }

  // Handle normalized or wrapped report objects
  const data = report.report || report;

  const attackChain = Array.isArray(data.attackChain)
    ? data.attackChain
    : typeof data.attackChain === 'string'
    ? [data.attackChain]
    : [];

  const iocs = Array.isArray(data.iocs)
    ? data.iocs
    : typeof data.iocs === 'string'
    ? [data.iocs]
    : [];

  const containment = Array.isArray(data.containment)
    ? data.containment
    : typeof data.containment === 'string'
    ? [data.containment]
    : [];

  return (
    <div className="space-y-4 rounded-lg border border-hairline/70 bg-void/60 p-4">
      {/* Executive Summary */}
      {data.executiveSummary && (
        <section>
          <h4 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-accent">
            Executive Summary
          </h4>
          <p className="mt-1.5 text-xs text-ink-primary leading-relaxed">
            {data.executiveSummary}
          </p>
        </section>
      )}

      {/* Metrics Row: Threat Level & Confidence */}
      <div className="grid grid-cols-2 gap-3 border-y border-hairline/40 py-3">
        <div>
          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
            Threat Level
          </span>
          <div className="mt-1">
            <SeverityBadge severity={data.threatLevel?.toLowerCase() || 'medium'} />
          </div>
        </div>

        <div>
          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
            Confidence
          </span>
          <div className="mt-1 flex items-center gap-2">
            <div className="h-2 w-24 overflow-hidden rounded-full bg-raised">
              <div
                className="h-full bg-accent rounded-full transition-all duration-500"
                style={{ width: `${Math.min(100, Math.max(0, data.confidence || 85))}%` }}
              />
            </div>
            <span className="font-mono text-xs font-semibold text-white">
              {data.confidence != null ? `${data.confidence}%` : '—'}
            </span>
          </div>
        </div>
      </div>

      {/* Attack Chain */}
      {attackChain.length > 0 && (
        <section>
          <h4 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
            Attack Chain
          </h4>
          <ol className="mt-2 space-y-1.5 text-xs text-ink-secondary">
            {attackChain.map((step, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="font-mono text-[10px] text-accent font-bold mt-0.5">
                  {idx + 1}.
                </span>
                <span className="leading-snug">{step}</span>
              </li>
            ))}
          </ol>
        </section>
      )}

      {/* Indicators of Compromise (IOCs) */}
      {iocs.length > 0 && (
        <section>
          <h4 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
            Indicators of Compromise
          </h4>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {iocs.map((ioc, idx) => (
              <span
                key={idx}
                className="rounded border border-hairline bg-raised px-2 py-0.5 font-mono text-[11px] text-ink-primary break-all max-w-full"
              >
                {ioc}
              </span>
            ))}
          </div>
        </section>
      )}

      {/* Recommended Containment */}
      {containment.length > 0 && (
        <section>
          <h4 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
            Recommended Containment
          </h4>
          <ul className="mt-1.5 space-y-1 text-xs text-emerald-300/90">
            {containment.map((action, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="font-bold">•</span>
                <span>{action}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}