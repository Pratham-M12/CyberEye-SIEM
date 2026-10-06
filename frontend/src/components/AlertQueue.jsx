// frontend/src/components/AlertQueue.jsx
import { useEffect, useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getAlerts } from '../api/siem.js';
import { getTimeRange } from '../constants/timeRange.js';
import { useWebSocket } from '../hooks/useWebSocket.js';
import SeverityBadge from './SeverityBadge.jsx';
import Panel from './ui/Panel';
import PanelHeader from './ui/PanelHeader';
import StatusDot from './ui/StatusDot';
import LoadingSkeleton from './ui/LoadingSkeleton';
import EmptyState from './ui/EmptyState';
import ErrorState from './ui/ErrorState';

const SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low'];

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export default function AlertQueue({
  onSelectAlert,
  selectedAlertId,
  timeRange = '24h',
  autoRefresh = true,
}) {
  const activeRange = getTimeRange(timeRange);

  const { data, isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ['alerts', 'queue'],
    queryFn: () => getAlerts({ pageSize: 50 }),
    refetchInterval: autoRefresh ? 30_000 : false,
    placeholderData: (prev) => prev,
  });

  const [alerts, setAlerts] = useState([]);
  const [freshIds, setFreshIds] = useState(() => new Set());
  const [severityFilter, setSeverityFilter] = useState('all');

  useEffect(() => {
    if (data?.alerts) {
      setAlerts(data.alerts);
    }
  }, [data]);

  const { connected } = useWebSocket((incoming) => {
    setAlerts((prev) => [incoming, ...prev].slice(0, 100));
    setFreshIds((prev) => new Set(prev).add(incoming.id));
    setTimeout(() => {
      setFreshIds((prev) => {
        const next = new Set(prev);
        next.delete(incoming.id);
        return next;
      });
    }, 1200);
  });

  const filteredAlerts = useMemo(() => {
    const cutoff = Date.now() - activeRange.ms;
    return alerts.filter((a) => {
      const ts = a['@timestamp'] || a.createdAt;
      const alertTime = ts ? new Date(ts).getTime() : 0;
      const matchesTime = !alertTime || alertTime >= cutoff;
      const matchesSev =
        severityFilter === 'all' ||
        a.severity?.toLowerCase() === severityFilter.toLowerCase();
      return matchesTime && matchesSev;
    });
  }, [alerts, severityFilter, activeRange.ms]);

  return (
    <Panel className="flex h-full flex-col">
      <PanelHeader
        icon="!"
        title="Alert Queue"
        subtitle={`Realtime Detection Engine • ${activeRange.label}`}
        right={
          <div className="flex items-center gap-3">
            {isFetching && !isLoading && (
              <span
                className="flex items-center gap-1.5 text-[11px] text-ink-muted"
                title="Updating alerts..."
              >
                <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
                <span className="hidden sm:inline">Syncing</span>
              </span>
            )}
            <StatusDot
              color={connected ? 'bg-green-500' : 'bg-red-500'}
              text={connected ? 'Live' : 'Disconnected'}
            />
          </div>
        }
      />

      {/* Severity Filter Tabs */}
      <div className="flex items-center gap-1 border-b border-hairline/60 bg-raised/70 px-4 py-2 overflow-x-auto">
        <span className="mr-1 text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
          Filter:
        </span>
        {SEVERITY_FILTERS.map((sev) => {
          const isActive = severityFilter === sev;
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`rounded px-2.5 py-1 text-[11px] font-mono capitalize transition ${
                isActive
                  ? 'bg-accent text-white font-semibold shadow-sm'
                  : 'text-ink-muted hover:bg-white/5 hover:text-ink-primary'
              }`}
            >
              {sev}
            </button>
          );
        })}
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Initial Loading Skeleton */}
        {isLoading && alerts.length === 0 && (
          <LoadingSkeleton variant="alert-list" count={6} />
        )}

        {/* API Error on Initial Load */}
        {isError && alerts.length === 0 && (
          <ErrorState
            title="Unable to load alerts"
            message="The SIEM API is temporarily unavailable."
            onRetry={() => refetch()}
            className="py-12"
          />
        )}

        {/* Non-destructive background error notice */}
        {isError && alerts.length > 0 && (
          <div className="p-3">
            <ErrorState
              compact
              message="Unable to refresh alerts. Showing cached telemetry."
              onRetry={() => refetch()}
            />
          </div>
        )}

        {/* Clean Empty State (Queue completely empty) */}
        {!isLoading && !isError && alerts.length === 0 && (
          <EmptyState
            icon="🛡️"
            title="No alerts detected"
            description="The rule engine evaluates telemetry every 30 seconds. Incidents violating detection thresholds will appear here automatically."
            className="py-12"
          />
        )}

        {/* Empty State when severity filter excludes all alerts */}
        {!isLoading &&
          !isError &&
          alerts.length > 0 &&
          filteredAlerts.length === 0 && (
            <EmptyState
              icon="🔍"
              title={`No ${severityFilter} alerts`}
              description={`No alerts matching "${severityFilter}" severity are currently open.`}
              action={
                <button
                  onClick={() => setSeverityFilter('all')}
                  className="rounded-lg border border-hairline bg-raised px-3 py-1.5 font-mono text-xs text-accent hover:border-accent"
                >
                  Show All Alerts ({alerts.length})
                </button>
              }
              className="py-10"
            />
          )}

        {/* Render Alert List */}
        {!isLoading && filteredAlerts.length > 0 && (
          <ul role="list" aria-label="Alerts queue">
            {filteredAlerts.map((alert) => {
              const isFresh = freshIds.has(alert.id);
              const isSelected = alert.id === selectedAlertId;
              return (
                <li key={alert.id}>
                  <button
                    onClick={() => onSelectAlert(alert.id)}
                    aria-label={`View alert ${alert.rule_name} on ${
                      alert.affected_host ?? alert.source_ip ?? 'system'
                    }`}
                    className={`block w-full rounded-none border-b border-l-4 border-hairline px-4 py-3 text-left transition-all duration-200 ease-out hover:bg-white/5 ${
                      isSelected ? 'bg-accent/10 border-l-accent' : ''
                    } ${
                      isFresh
                        ? 'border-l-accent bg-accent/15 animate-pulse-in'
                        : isSelected
                        ? 'border-l-accent'
                        : 'border-l-transparent'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-base font-semibold text-ink-primary">
                        {alert.rule_name}
                      </span>
                      <div className="ml-3 shrink-0">
                        <SeverityBadge severity={alert.severity} />
                      </div>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between gap-2 text-xs text-ink-secondary">
                      <span className="truncate text-sm font-mono text-ink-muted">
                        {alert.affected_host ?? alert.source_ip ?? 'unknown host'}
                      </span>
                      <span className="tabular font-mono text-xs text-ink-muted">
                        {formatTime(alert['@timestamp'])}
                      </span>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Panel>
  );
}
