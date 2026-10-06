// frontend/src/components/AlertDrawer.jsx
import React, { useState, useEffect, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import SeverityBadge from './SeverityBadge.jsx';
import AlertTimeline from './AlertTimeline.jsx';
import JsonViewer from './JsonViewer.jsx';
import AIInvestigation from './AIInvestigation.jsx';
import LoadingSkeleton from './ui/LoadingSkeleton.jsx';
import ErrorState from './ui/ErrorState.jsx';
import { getAlert, investigateAlert, setAlertStatus } from '../api/siem.js';
import { useAuth } from '../context/AuthContext.jsx';

const RULE_DESCRIPTIONS = {
  R1: 'Fires when a single source IP produces 5 or more failed Windows logins (Event ID 4625) within a 60 second window — the signature of an automated brute-force attempt.',
  R2: 'Escalation of R1: a brute-force burst from an IP followed by a successful login (Event ID 4624) from that same IP within 5 minutes — the credentials likely worked.',
  R3: 'Fires when a single source IP touches 10 or more distinct destination ports within 30 seconds, per Snort — typical of automated port/service discovery ahead of an intrusion attempt.',
  R4: 'Fires when an Apache/Nginx request URI matches a known SQL injection or XSS pattern — someone is probing (or exploiting) a public-facing web application.',
  R5: 'Fires when a privilege is assigned (Event ID 4672) to a user within 5 minutes of that same user logging in (Event ID 4624) — a fast escalation-after-login pattern worth confirming was expected.',
};

const SUGGESTED_ACTIONS = {
  R1: 'Block the source IP at the perimeter firewall and confirm the targeted account has not been locked out or compromised.',
  R2: 'Force a password reset on the affected account immediately, block the source IP, and review the account for any activity since the successful login.',
  R3: 'Add the source IP to a watchlist, confirm whether it maps to a known vulnerability scanner, and block it if unauthorized.',
  R4: 'Inspect the web server access logs for a successful exploit response (200/500), apply a WAF rule for the matched pattern, and patch the vulnerable endpoint.',
  R5: 'Confirm the privilege grant was authorized (change ticket, admin request); if not, revoke it and investigate the account for compromise.',
};

/**
 * Safely extracts a property from an object checking both flat and nested dotted keys.
 */
function getField(obj, ...paths) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const path of paths) {
    if (obj[path] !== undefined && obj[path] !== null && obj[path] !== '') {
      return obj[path];
    }
    if (path.includes('.')) {
      const parts = path.split('.');
      let cur = obj;
      let found = true;
      for (const part of parts) {
        if (cur && typeof cur === 'object' && part in cur) {
          cur = cur[part];
        } else {
          found = false;
          break;
        }
      }
      if (found && cur !== undefined && cur !== null && cur !== '') {
        return cur;
      }
    }
  }
  return undefined;
}

/**
 * Checks whether an IP belongs to RFC 1918 or loopback private subnets.
 */
function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const clean = ip.trim();
  return (
    clean.startsWith('10.') ||
    clean.startsWith('192.168.') ||
    clean.startsWith('127.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(clean) ||
    clean === '::1' ||
    clean === 'localhost'
  );
}

/**
 * Safely resolves threat intelligence details from the alert or its evidence events.
 */
function extractThreatIntel(alert) {
  if (!alert) return { status: 'unavailable' };

  // 1. Direct alert-level threat intelligence
  const alertThreat =
    alert.threat_intel ||
    alert.abuseipdb ||
    (alert.threat && typeof alert.threat === 'object' ? alert.threat : null);

  if (
    alertThreat &&
    (alertThreat.score !== undefined ||
      alertThreat.is_malicious !== undefined ||
      alertThreat.isMalicious !== undefined)
  ) {
    return {
      status: 'enriched',
      score: alertThreat.score ?? alertThreat.abuseConfidenceScore ?? 0,
      isMalicious: Boolean(
        alertThreat.is_malicious ??
          alertThreat.isMalicious ??
          (alertThreat.score >= 50)
      ),
      totalReports:
        alertThreat.totalReports ?? alertThreat.total_reports ?? null,
      countryCode:
        alertThreat.countryCode ?? alertThreat.country_code ?? null,
      isp: alertThreat.isp ?? null,
      domain: alertThreat.domain ?? null,
      lastReportedAt:
        alertThreat.lastReportedAt ?? alertThreat.last_reported_at ?? null,
    };
  }

  // 2. Evidence-level threat intelligence
  for (const ev of alert.evidence || []) {
    const evThreat =
      ev.threat ||
      (ev['threat.score'] !== undefined || ev['threat.is_malicious'] !== undefined
        ? {
            score: ev['threat.score'],
            is_malicious: ev['threat.is_malicious'],
            totalReports: ev['threat.total_reports'],
            countryCode: ev['threat.country_code'],
            isp: ev['threat.isp'],
            domain: ev['threat.domain'],
          }
        : null);

    if (
      evThreat &&
      (evThreat.score !== undefined || evThreat.is_malicious !== undefined)
    ) {
      return {
        status: 'enriched',
        score: evThreat.score ?? 0,
        isMalicious: Boolean(
          evThreat.is_malicious ?? (evThreat.score >= 50)
        ),
        totalReports: evThreat.totalReports ?? evThreat.total_reports ?? null,
        countryCode: evThreat.countryCode ?? evThreat.country_code ?? null,
        isp: evThreat.isp ?? null,
        domain: evThreat.domain ?? null,
        lastReportedAt: evThreat.lastReportedAt ?? null,
      };
    }
  }

  // 3. Check if source IP is private
  const sourceIp =
    alert.source_ip ||
    getField(alert, 'source.ip') ||
    getField(alert.evidence?.[0], 'source.ip', 'source_ip');

  if (sourceIp && isPrivateIp(sourceIp)) {
    return {
      status: 'private_ip',
      ip: sourceIp,
    };
  }

  return {
    status: 'not_enriched',
    ip: sourceIp || null,
  };
}

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString([], {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export default function AlertDrawer({ alertId, onClose }) {
  const queryClient = useQueryClient();
  const { hasRole } = useAuth();
  const canTriage = hasRole('admin', 'analyst');
  const [copiedId, setCopiedId] = useState(false);

  // Close on Escape key press
  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape') {
        onClose();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const {
    data: alert,
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ['alert', alertId],
    queryFn: () => getAlert(alertId),
    enabled: Boolean(alertId),
  });

  const investigationMutation = useMutation({
    mutationFn: () => investigateAlert(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ['alert', alertId],
      });
    },
  });

  const statusMutation = useMutation({
    mutationFn: (status) => setAlertStatus(alertId, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert', alertId] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });

  // Extract available context parameters without empty values
  const contextItems = useMemo(() => {
    if (!alert) return [];
    const firstEv = alert.evidence?.[0];

    const sourceIp =
      alert.source_ip ||
      getField(alert, 'source.ip') ||
      getField(firstEv, 'source.ip', 'source_ip');

    const destIp =
      alert.destination_ip ||
      getField(alert, 'destination.ip') ||
      getField(firstEv, 'destination.ip', 'destination_ip');

    const destPort =
      alert.destination_port ||
      getField(alert, 'destination.port') ||
      getField(firstEv, 'destination.port', 'destination_port');

    const host =
      alert.affected_host ||
      getField(alert, 'host.name', 'host') ||
      getField(firstEv, 'host.name', 'host');

    const user =
      alert.affected_user ||
      getField(alert, 'user.name', 'user') ||
      getField(firstEv, 'user.name', 'user');

    return [
      sourceIp && {
        label: 'Source IP',
        value: sourceIp,
        mono: true,
        icon: '🌐',
      },
      destIp && {
        label: 'Destination IP',
        value: destIp,
        mono: true,
        icon: '🎯',
      },
      destPort && {
        label: 'Destination Port',
        value: String(destPort),
        mono: true,
        icon: '🔌',
      },
      host && {
        label: 'Target Host',
        value: host,
        mono: true,
        icon: '💻',
      },
      user && {
        label: 'Target User',
        value: user,
        mono: true,
        icon: '👤',
      },
    ].filter(Boolean);
  }, [alert]);

  const threatIntel = useMemo(() => extractThreatIntel(alert), [alert]);

  if (!alertId) return null;

  function handleCopyId() {
    if (alert?.id) {
      navigator.clipboard.writeText(alert.id);
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 1500);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm transition-opacity"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Alert Details Drawer"
    >
      <div
        className="flex h-full w-full max-w-2xl sm:max-w-3xl lg:max-w-4xl flex-col sm:border-l sm:border-hairline bg-panel shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Loading State */}
        {isLoading && (
          <div className="flex flex-col h-full">
            <div className="flex items-center justify-between border-b border-hairline p-5 bg-raised/50">
              <span className="font-mono text-xs text-ink-muted">
                Loading incident details...
              </span>
              <button
                onClick={onClose}
                aria-label="Close drawer"
                className="rounded-md border border-hairline px-3 py-1 font-mono text-xs text-ink-muted hover:text-ink-primary hover:border-accent transition"
              >
                close (esc)
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-6">
              <LoadingSkeleton variant="drawer" />
            </div>
          </div>
        )}

        {/* Error State */}
        {!isLoading && (isError || !alert) && (
          <div className="flex flex-col h-full">
            <div className="flex items-center justify-between border-b border-hairline p-5 bg-raised/50">
              <span className="font-mono text-xs text-severity-high">
                Incident Unavailable
              </span>
              <button
                onClick={onClose}
                aria-label="Close drawer"
                className="rounded-md border border-hairline px-3 py-1 font-mono text-xs text-ink-muted hover:text-ink-primary hover:border-accent transition"
              >
                close (esc)
              </button>
            </div>
            <div className="flex-1 flex items-center justify-center p-6">
              <ErrorState
                title="Unable to load alert details"
                message="The requested incident could not be retrieved from Elasticsearch."
                onRetry={() => refetch()}
                className="py-12"
              />
            </div>
          </div>
        )}

        {/* Successful Data State */}
        {!isLoading && alert && (
          <>
            {/* 1. Alert Summary Sticky Header */}
            <header className="sticky top-0 z-20 border-b border-hairline bg-raised/95 backdrop-blur-md px-4 sm:px-6 py-3.5 sm:py-4 shadow-sm">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  {/* Badges Row: Severity, Rule ID, Status */}
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <SeverityBadge severity={alert.severity} />
                    <span className="rounded bg-black/40 border border-hairline/80 px-2 py-0.5 font-mono text-[11px] font-semibold text-accent">
                      {alert.rule_id}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider border ${
                        alert.status === 'open'
                          ? 'bg-emerald-950/60 text-emerald-300 border-emerald-700/50'
                          : alert.status === 'acknowledged'
                          ? 'bg-yellow-950/60 text-yellow-300 border-yellow-700/50'
                          : 'bg-neutral-800 text-neutral-300 border-neutral-700'
                      }`}
                    >
                      {alert.status}
                    </span>
                  </div>

                  {/* Rule Name Title */}
                  <h2 className="font-mono text-lg sm:text-xl font-bold tracking-tight text-ink-primary break-words">
                    {alert.rule_name}
                  </h2>

                  {/* Metadata: Timestamp & Alert ID */}
                  <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-xs text-ink-muted">
                    <span className="flex items-center gap-1.5 tabular text-ink-secondary">
                      <span>🕒</span>
                      <span>{formatTime(alert['@timestamp'] || alert.createdAt)}</span>
                    </span>

                    <span className="flex items-center gap-1 text-[11px] text-ink-dim">
                      <span>ID:</span>
                      <button
                        type="button"
                        onClick={handleCopyId}
                        title="Click to copy Alert ID"
                        className="font-mono text-ink-muted hover:text-accent transition underline underline-offset-2 select-all max-w-[180px] sm:max-w-none truncate inline-block align-bottom"
                      >
                        {alert.id}
                      </button>
                      {copiedId && (
                        <span className="text-[10px] font-semibold text-accent ml-1 animate-fade-in">
                          Copied!
                        </span>
                      )}
                    </span>
                  </div>
                </div>

                {/* Close Button */}
                <button
                  onClick={onClose}
                  aria-label="Close alert drawer"
                  title="Close drawer (Esc)"
                  className="rounded-lg border border-hairline bg-void/50 p-2 text-ink-muted hover:text-white hover:border-accent transition shrink-0"
                >
                  <svg
                    className="h-4 w-4"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth="2.5"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      d="M6 18L18 6M6 6l12 12"
                    />
                  </svg>
                </button>
              </div>
            </header>

            {/* Scrollable Content Body */}
            <div className="flex-1 overflow-y-auto px-4 sm:px-6 py-4 sm:py-6 space-y-5 sm:space-y-6">
              {/* 2. Source / Target Context Card Grid */}
              {contextItems.length > 0 && (
                <section>
                  <h3 className="mb-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    Incident Context
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {contextItems.map((item) => (
                      <div
                        key={item.label}
                        className="rounded-lg border border-hairline/80 bg-void/60 p-3 shadow-sm"
                      >
                        <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-ink-dim">
                          <span>{item.icon}</span>
                          <span>{item.label}</span>
                        </div>
                        <p
                          className={`mt-1 text-sm font-semibold text-ink-primary truncate ${
                            item.mono ? 'font-mono' : ''
                          }`}
                          title={item.value}
                        >
                          {item.value}
                        </p>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* 3. Detection Information & MITRE ATT&CK Mapping */}
              <section className="rounded-lg border border-hairline/80 bg-raised/30 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    Detection Information
                  </h3>
                  <span className="font-mono text-xs text-ink-dim">
                    {alert.evidence?.length ?? 0} Evidence Events
                  </span>
                </div>

                <p className="text-xs text-ink-secondary leading-relaxed">
                  {RULE_DESCRIPTIONS[alert.rule_id] ||
                    'Automated SIEM detection correlation rule.'}
                </p>

                {/* MITRE ATT&CK Card */}
                {(alert.mitre_technique_id || alert.mitre_tactic) && (
                  <div className="rounded-lg border border-hairline bg-void/80 p-3">
                    <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
                      MITRE ATT&amp;CK Framework Mapping
                    </span>
                    <div className="mt-1 flex flex-wrap items-baseline gap-2">
                      <span className="font-mono text-sm font-bold text-accent">
                        {alert.mitre_technique_id}{' '}
                        {alert.mitre_technique_name
                          ? `— ${alert.mitre_technique_name}`
                          : ''}
                      </span>
                    </div>
                    {alert.mitre_tactic && (
                      <p className="mt-1 text-xs text-ink-muted">
                        Tactic:{' '}
                        <span className="text-ink-secondary font-medium">
                          {alert.mitre_tactic}
                        </span>
                      </p>
                    )}
                  </div>
                )}
              </section>

              {/* 4. Threat Intelligence (AbuseIPDB) */}
              <section>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    Threat Intelligence (AbuseIPDB)
                  </h3>
                  <span
                    className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider border ${
                      threatIntel.status === 'enriched'
                        ? threatIntel.isMalicious
                          ? 'bg-red-950/60 text-red-300 border-red-700/50'
                          : 'bg-emerald-950/60 text-emerald-300 border-emerald-700/50'
                        : threatIntel.status === 'private_ip'
                        ? 'bg-sky-950/50 text-sky-300 border-sky-800/50'
                        : 'bg-raised text-ink-muted border-hairline'
                    }`}
                  >
                    {threatIntel.status === 'enriched'
                      ? threatIntel.isMalicious
                        ? 'Malicious IP'
                        : 'Clean Reputation'
                      : threatIntel.status === 'private_ip'
                      ? 'RFC 1918 Private'
                      : 'Not Enriched'}
                  </span>
                </div>

                {threatIntel.status === 'enriched' && (
                  <div className="rounded-lg border border-hairline bg-void p-4">
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                      <div>
                        <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
                          Confidence Score
                        </span>
                        <p
                          className={`mt-0.5 font-mono text-sm font-bold ${
                            threatIntel.score >= 50
                              ? 'text-severity-critical'
                              : threatIntel.score > 0
                              ? 'text-severity-high'
                              : 'text-emerald-400'
                          }`}
                        >
                          {threatIntel.score}%
                        </p>
                      </div>

                      <div>
                        <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
                          Malicious Status
                        </span>
                        <p
                          className={`mt-0.5 font-mono text-sm font-bold ${
                            threatIntel.isMalicious
                              ? 'text-severity-critical'
                              : 'text-emerald-400'
                          }`}
                        >
                          {threatIntel.isMalicious
                            ? 'Confirmed Malicious'
                            : 'Benign / Clean'}
                        </p>
                      </div>

                      {threatIntel.totalReports != null && (
                        <div>
                          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
                            Total Reports
                          </span>
                          <p className="mt-0.5 font-mono text-sm text-ink-primary">
                            {threatIntel.totalReports.toLocaleString()}
                          </p>
                        </div>
                      )}

                      {threatIntel.countryCode && (
                        <div>
                          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
                            Country
                          </span>
                          <p className="mt-0.5 font-mono text-sm text-ink-primary">
                            {threatIntel.countryCode}
                          </p>
                        </div>
                      )}

                      {threatIntel.isp && (
                        <div>
                          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
                            ISP
                          </span>
                          <p
                            className="mt-0.5 font-mono text-sm text-ink-primary truncate"
                            title={threatIntel.isp}
                          >
                            {threatIntel.isp}
                          </p>
                        </div>
                      )}

                      {threatIntel.domain && (
                        <div>
                          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
                            Domain
                          </span>
                          <p
                            className="mt-0.5 font-mono text-sm text-ink-primary truncate"
                            title={threatIntel.domain}
                          >
                            {threatIntel.domain}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {threatIntel.status === 'private_ip' && (
                  <div className="rounded-lg border border-hairline/60 bg-void/50 p-3.5">
                    <div className="flex items-start gap-2.5">
                      <span className="text-sm">ℹ️</span>
                      <div>
                        <p className="font-mono text-xs text-ink-primary">
                          Internal Lab Telemetry ({threatIntel.ip})
                        </p>
                        <p className="mt-1 text-xs text-ink-muted leading-relaxed">
                          RFC 1918 private network address. External AbuseIPDB threat intelligence queries are bypassed for isolated lab subnets.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {threatIntel.status === 'not_enriched' && (
                  <div className="rounded-lg border border-hairline/60 bg-void/50 p-3.5">
                    <div className="flex items-start gap-2.5">
                      <span className="text-sm text-ink-muted">🛡️</span>
                      <div>
                        <p className="font-mono text-xs text-ink-muted">
                          Enrichment Record Unavailable
                        </p>
                        <p className="mt-1 text-xs text-ink-dim leading-relaxed">
                          No external threat intelligence reputation records are currently attached to this incident.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </section>

              {/* 5. AI Incident Investigation */}
              <section>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    AI Incident Investigation
                  </h3>
                  {canTriage &&
                    !investigationMutation.data &&
                    !alert.ai_investigation && (
                      <button
                        type="button"
                        onClick={() => investigationMutation.mutate()}
                        disabled={investigationMutation.isPending}
                        aria-label="Generate AI incident investigation"
                        className="rounded-lg border border-accent/40 bg-accent/15 px-3 py-1 font-mono text-xs font-semibold text-accent hover:bg-accent hover:text-white transition disabled:opacity-40 shadow-sm"
                      >
                        {investigationMutation.isPending
                          ? 'Investigating...'
                          : '🔍 Investigate with AI'}
                      </button>
                    )}
                  {!canTriage && !alert.ai_investigation && (
                    <span className="text-[11px] text-ink-muted italic">
                      Investigation restricted (Analyst/Admin only)
                    </span>
                  )}
                </div>

                {/* AI Investigation Pending State */}
                {investigationMutation.isPending && (
                  <div
                    className="rounded-lg border border-accent/40 bg-accent/5 p-4 animate-pulse"
                    role="status"
                    aria-busy="true"
                  >
                    <div className="flex items-center gap-2 text-accent text-xs font-mono font-semibold">
                      <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-accent border-t-transparent" />
                      <span>Synthesizing Groq LLM Incident Report...</span>
                    </div>
                    <p className="mt-1.5 text-xs text-ink-muted leading-relaxed">
                      Analyzing alert metadata, MITRE ATT&amp;CK techniques, and raw telemetry evidence.
                    </p>
                  </div>
                )}

                {/* AI Investigation Error State */}
                {investigationMutation.isError && (
                  <div className="mt-2">
                    <ErrorState
                      compact
                      message="AI investigation service is temporarily unavailable."
                      onRetry={() => investigationMutation.mutate()}
                    />
                  </div>
                )}

                {/* AI Investigation Report */}
                {!investigationMutation.isPending && (
                  <AIInvestigation
                    report={
                      investigationMutation.data?.investigation ??
                      alert.ai_investigation ??
                      null
                    }
                  />
                )}
              </section>

              {/* 6. Suggested Response Action */}
              <section>
                <h3 className="mb-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Suggested Response Action
                </h3>
                <div className="rounded-lg border border-severity-high/30 bg-severity-high/5 p-3.5 text-xs text-ink-primary leading-relaxed">
                  <div className="flex items-start gap-2">
                    <span className="text-severity-high font-bold shrink-0">🛡️ Playbook:</span>
                    <span>
                      {SUGGESTED_ACTIONS[alert.rule_id] ||
                        'Review system logs and isolate the affected host if anomalous behavior persists.'}
                    </span>
                  </div>
                </div>
              </section>

              {/* 7. Contributing Raw Events Timeline */}
              <section>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    Contributing Evidence Events ({alert.evidence?.length ?? 0})
                  </h3>
                  <span className="text-[10px] font-mono text-ink-dim">
                    Correlated telemetry
                  </span>
                </div>

                <div className="space-y-3 max-h-[440px] overflow-y-auto pr-1">
                  {(alert.evidence ?? []).length === 0 ? (
                    <div className="rounded-lg border border-hairline/60 bg-void/50 p-4 text-center">
                      <p className="font-mono text-xs text-ink-muted">
                        No contributing log telemetry attached to this alert.
                      </p>
                    </div>
                  ) : (
                    (alert.evidence ?? []).map((event, idx) => (
                      <EvidenceEventCard
                        key={idx}
                        event={event}
                        index={idx + 1}
                      />
                    ))
                  )}
                </div>
              </section>

              {/* 8. Incident Lifecycle History */}
              <section>
                <h3 className="mb-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Incident History &amp; Audit Trail
                </h3>
                <div className="rounded-lg border border-hairline bg-void/80 p-4">
                  <AlertTimeline history={alert.history} />
                </div>
              </section>

              {/* 9. Raw Alert JSON Inspector */}
              <section>
                <h3 className="mb-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Raw Alert Document
                </h3>
                <JsonViewer data={alert} />
              </section>
            </div>

            {/* 10. Sticky Triage Actions Footer */}
            <footer className="sticky bottom-0 z-20 border-t border-hairline bg-panel/95 backdrop-blur-md p-3.5 sm:p-4 shadow-lg">
              {statusMutation.isError && (
                <div className="mb-3">
                  <ErrorState
                    compact
                    message="Failed to update alert status. Please try again."
                  />
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] uppercase tracking-wider text-ink-dim">
                    Current Status:
                  </span>
                  <span
                    className={`rounded px-2.5 py-0.5 font-mono text-xs font-bold uppercase ${
                      alert.status === 'open'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50'
                        : alert.status === 'acknowledged'
                        ? 'bg-yellow-950 text-yellow-300 border border-yellow-700/50'
                        : 'bg-neutral-800 text-neutral-300 border border-neutral-700'
                    }`}
                  >
                    {alert.status}
                  </span>
                </div>

                {canTriage ? (
                  <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
                    {['open', 'acknowledged', 'closed'].map((targetStatus) => {
                      const isCurrent = alert.status === targetStatus;
                      return (
                        <button
                          key={targetStatus}
                          type="button"
                          onClick={() => statusMutation.mutate(targetStatus)}
                          disabled={isCurrent || statusMutation.isPending}
                          aria-label={`Mark alert as ${targetStatus}`}
                          className={`flex-1 sm:flex-initial text-center rounded-lg px-3 py-2 sm:py-1.5 min-h-[38px] font-mono text-xs font-semibold uppercase transition ${
                            isCurrent
                              ? 'border border-accent/60 bg-accent/20 text-accent cursor-default'
                              : 'border border-hairline bg-raised hover:border-accent hover:text-white text-ink-secondary disabled:opacity-40'
                          }`}
                        >
                          {statusMutation.isPending &&
                          statusMutation.variables === targetStatus ? (
                            <span className="flex items-center gap-1.5">
                              <span className="h-3 w-3 animate-spin rounded-full border-2 border-accent border-t-transparent" />
                              <span>Updating...</span>
                            </span>
                          ) : (
                            `Mark ${targetStatus}`
                          )}
                        </button>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-ink-muted italic">
                    Read-only operator session (Analyst/Admin required for triage).
                  </div>
                )}
              </div>
            </footer>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * Clean analyst card for individual contributing evidence events.
 */
function EvidenceEventCard({ event, index }) {
  const [showRaw, setShowRaw] = useState(false);

  const evTs = getField(event, '@timestamp', 'timestamp', 'createdAt');
  const evType = getField(event, 'event.type', 'eventType');
  const evSource = getField(event, 'log.source', 'source');
  const evId = getField(event, 'event.id', 'winlog.event_id', 'event_id');
  const evSrcIp = getField(event, 'source.ip', 'source_ip');
  const evDestIp = getField(event, 'destination.ip', 'destination_ip');
  const evDestPort = getField(event, 'destination.port', 'destination_port');
  const evHost = getField(event, 'host.name', 'host');
  const evUser = getField(event, 'user.name', 'user');
  const evRawMessage = event.raw_message || event.message;

  const eventContext = [
    evSrcIp && { label: 'Src IP', value: evSrcIp },
    evDestIp && {
      label: 'Dest IP',
      value: evDestPort ? `${evDestIp}:${evDestPort}` : evDestIp,
    },
    evHost && { label: 'Host', value: evHost },
    evUser && { label: 'User', value: evUser },
  ].filter(Boolean);

  return (
    <div className="rounded-lg border border-hairline/80 bg-void/90 p-3.5 space-y-2.5 transition hover:border-hairline">
      {/* Event Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-hairline/50 pb-2">
        <div className="flex items-center gap-2">
          <span className="rounded bg-raised border border-hairline/60 px-1.5 py-0.5 font-mono text-[10px] font-bold text-accent">
            #{index}
          </span>
          {evSource && (
            <span className="font-mono text-xs uppercase font-semibold text-ink-primary">
              {evSource}
            </span>
          )}
          {evType && (
            <span className="rounded bg-panel px-2 py-0.5 font-mono text-[10px] text-ink-secondary border border-hairline/40">
              {evType}
            </span>
          )}
          {evId && (
            <span className="rounded bg-panel px-2 py-0.5 font-mono text-[10px] text-ink-dim border border-hairline/40">
              Event ID: {evId}
            </span>
          )}
        </div>

        <span className="tabular font-mono text-[11px] text-ink-muted">
          {formatTime(evTs)}
        </span>
      </div>

      {/* Structured Parameters Grid */}
      {eventContext.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
          {eventContext.map((c) => (
            <div key={c.label} className="min-w-0">
              <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
                {c.label}:
              </span>{' '}
              <span
                className="font-mono text-ink-primary font-medium truncate inline-block max-w-full align-bottom"
                title={c.value}
              >
                {c.value}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Raw Message Snippet */}
      {evRawMessage && (
        <div className="rounded bg-black/50 border border-hairline/40 p-2 font-mono text-[11px] text-ink-secondary break-all">
          {evRawMessage}
        </div>
      )}

      {/* Expandable Raw JSON */}
      <div>
        <button
          type="button"
          onClick={() => setShowRaw((prev) => !prev)}
          aria-expanded={showRaw}
          className="font-mono text-[11px] text-accent hover:underline flex items-center gap-1"
        >
          <span>{showRaw ? '▲ Hide raw event' : '▼ Inspect raw event JSON'}</span>
        </button>

        {showRaw && (
          <pre className="mt-2 overflow-x-auto rounded bg-black/75 p-3 font-mono text-[10px] text-ink-primary border border-hairline/60 max-h-60 overflow-y-auto whitespace-pre-wrap break-all sm:whitespace-pre sm:break-normal">
            {JSON.stringify(event, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}
