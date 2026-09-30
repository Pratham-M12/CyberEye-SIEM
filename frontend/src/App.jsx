import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getSummary } from './api/siem.js';
import AlertQueue from './components/AlertQueue.jsx';
import EventTimeline from './components/EventTimeline.jsx';
import TopAttackers from './components/TopAttackers.jsx';
import LogExplorer from './components/LogExplorer.jsx';
import AlertDrawer from './components/AlertDrawer.jsx';
import UploadPanel from './components/UploadPanel.jsx';

export default function App() {
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [ipFilter, setIpFilter] = useState(null);

  const { data: summary } = useQuery({
    queryKey: ['stats', 'summary'],
    queryFn: getSummary,
    refetchInterval: 30_000,
  });

  return (
    <div className="min-h-screen bg-void">
    <header className="border-b border-hairline bg-panel shadow-panel">
      <div className="mx-auto flex max-w-[1700px] items-center justify-between px-8 py-5">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-panel bg-accent text-xl font-bold text-white shadow">
            S
          </div>
          <div>
            <h1 className="text-3xl font-semibold tracking-wide text-white">
              Security Information & Event Management
            </h1>
            <p className="mt-1 text-sm text-ink-secondary">
              Enterprise Threat Monitoring Dashboard
            </p>
          </div>
        </div>
        <div className="flex gap-4">
          <MetricCard
            title="TOTAL EVENTS"
            value={summary?.events_last_24h ?? "-"}
          />
          <MetricCard
            title="OPEN ALERTS"
            value={summary?.open_alerts ?? "-"}
          />
          <MetricCard
            title="CRITICAL"
            value={summary?.open_critical_alerts ?? "-"}
            danger
          />
        </div>
      </div>
    </header>

      <main className="mx-auto grid max-w-[1700px] grid-cols-1 gap-4 p-8 lg:grid-cols-[380px_1fr]">
        <div className="lg:row-span-2 lg:h-[calc(100vh-8rem)]">
          <AlertQueue onSelectAlert={setSelectedAlertId} selectedAlertId={selectedAlertId} />
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <EventTimeline />
          <TopAttackers onSelectIp={setIpFilter} selectedIp={ipFilter} />
        </div>

        <div className="space-y-4 xl:col-span-1">
          <UploadPanel />
          <LogExplorer ipFilter={ipFilter} onClearIpFilter={() => setIpFilter(null)} />
        </div>
      </main>

      <AlertDrawer alertId={selectedAlertId} onClose={() => setSelectedAlertId(null)} />
    </div>
  );
}

function MetricCard({  title,value,danger  })
{
    return(
        <div className="w-36 rounded-panel border border-hairline bg-raised px-5 py-3 shadow-panel">
            <div
                className={`text-3xl font-bold ${
                    danger
                        ? "text-severity-critical"
                        : "text-accent"
                }`}
            >
                {value}
            </div>
            <div className="mt-2 text-xs uppercase tracking-widest text-ink-muted">
                {title}
            </div>
        </div>
    );
}
