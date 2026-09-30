// frontend/src/components/AlertQueue.jsx
import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getAlerts } from '../api/siem.js';
import { useWebSocket } from '../hooks/useWebSocket.js';
import SeverityBadge from './SeverityBadge.jsx';
import Panel from "./ui/Panel";
import PanelHeader from "./ui/PanelHeader";
import StatusDot from "./ui/StatusDot";

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function AlertQueue({ onSelectAlert, selectedAlertId }) {
  const { data, isLoading } = useQuery({
    queryKey: ['alerts', 'queue'],
    queryFn: () => getAlerts({ pageSize: 50 }),
  });

  const [alerts, setAlerts] = useState([]);
  const [freshIds, setFreshIds] = useState(() => new Set());

  useEffect(() => {
    if (data?.alerts) setAlerts(data.alerts);
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

  return (
    <Panel className="flex h-full flex-col">
    <PanelHeader
        icon="!"
        title="Alert Queue"
        subtitle="Realtime Detection Engine"
        right={
            <StatusDot
                color={connected ? "bg-green-500" : "bg-red-500"}
                text={connected ? "Live" : "Disconnected"}
            />
        }
    />
      <div className="flex-1 overflow-y-auto">
        {isLoading && (
          <div className="p-4 text-sm text-ink-muted">Loading alerts…</div>
        )}

        {!isLoading && alerts.length === 0 && (
          <div className="p-6 text-center text-sm text-ink-muted">
            No alerts yet. The rule engine checks every 30s — they'll appear here the moment
            one fires.
          </div>
        )}

        <ul>
          {alerts.map((alert) => {
            const isFresh = freshIds.has(alert.id);
            const isSelected = alert.id === selectedAlertId;
            return (
              <li key={alert.id}>
                <button
                  onClick={() => onSelectAlert(alert.id)}
                  className={`block w-full rounded-none transition-all duration-200 ease-out border-b border-l-2 border-hairline px-4 py-3 text-left transition-colors duration-700 hover:bg-white/5 ${
                    isSelected ? 'bg-accent/10' : ''
                  } ${
                    isFresh
                      ? 'border-l-4 border-l-accent bg-accent/10 animate-pulse-in'
                      : 'border-l-4 border-l-transparent'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-base font-semibold text-ink-primary">
                      {alert.rule_name}
                    </span>
                    <div className="ml-3">
                      <SeverityBadge severity={alert.severity} />
                    </div>
                  </div>
                  <div className="mt-1.5 flex items-center justify-between gap-2 text-xs text-ink-secondary">
                    <span className="truncate text-sm">
                      {alert.affected_host ?? alert.source_ip ?? 'unknown host'}
                    </span>
                    <span className="tabular text-xs">{formatTime(alert['@timestamp'])}</span>
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </Panel>
  );
}
