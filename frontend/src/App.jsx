import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getSummary } from './api/siem.js';
import { useAuth } from './context/AuthContext.jsx';
import LoginView from './components/LoginView.jsx';
import UserManagementModal from './components/UserManagementModal.jsx';
import AlertQueue from './components/AlertQueue.jsx';
import EventTimeline from './components/EventTimeline.jsx';
import TopAttackers from './components/TopAttackers.jsx';
import LogExplorer from './components/LogExplorer.jsx';
import AlertDrawer from './components/AlertDrawer.jsx';
import UploadPanel from './components/UploadPanel.jsx';

export default function App() {
  const { user, isAuthenticated, logout, hasRole } = useAuth();
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [ipFilter, setIpFilter] = useState(null);
  const [userModalOpen, setUserModalOpen] = useState(false);

  const { data: summary } = useQuery({
    queryKey: ['stats', 'summary'],
    queryFn: getSummary,
    enabled: isAuthenticated,
    refetchInterval: 30_000,
  });

  // If unauthenticated, present secure CyberEye login interface
  if (!isAuthenticated) {
    return <LoginView />;
  }

  const role = user?.role?.toUpperCase() || 'USER';
  const isAdmin = hasRole('admin');

  return (
    <div className="min-h-screen bg-void">
      <header className="border-b border-hairline bg-panel shadow-panel">
        <div className="mx-auto flex max-w-[1700px] flex-wrap items-center justify-between gap-4 px-8 py-4">
          {/* Logo & Platform Info */}
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-panel bg-accent text-xl font-bold text-white shadow">
              C
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-wide text-white">
                CyberEye SIEM
              </h1>
              <p className="text-xs text-ink-secondary">
                Enterprise Threat Monitoring Dashboard
              </p>
            </div>
          </div>

          {/* Metric Cards */}
          <div className="flex flex-wrap items-center gap-3">
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

          {/* Operator Profile, Role Badge & Session Controls */}
          <div className="flex items-center gap-3 border-l border-hairline pl-4">
            <div className="text-right">
              <div className="text-sm font-semibold text-white">
                {user?.username}
              </div>
              <div className="mt-0.5">
                <span
                  className={`inline-block px-2 py-0.5 text-[10px] font-bold tracking-wider rounded uppercase ${
                    role === 'ADMIN'
                      ? 'bg-red-950 text-red-300 border border-red-800/50'
                      : role === 'ANALYST'
                      ? 'bg-blue-950 text-blue-300 border border-blue-800/50'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800/50'
                  }`}
                >
                  {role}
                </span>
              </div>
            </div>

            {/* Admin-only User Management Action */}
            {isAdmin && (
              <button
                onClick={() => setUserModalOpen(true)}
                className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/20 transition"
                title="Manage operator accounts and RBAC permissions"
              >
                ⚙ User Mgmt
              </button>
            )}

            {/* Logout Action */}
            <button
              onClick={() => logout()}
              className="rounded-lg border border-hairline bg-raised px-3 py-1.5 text-xs font-medium text-ink-secondary hover:bg-red-950/40 hover:text-red-300 hover:border-red-700/50 transition"
              title="End active session"
            >
              Logout
            </button>
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

      {/* Admin User Management Modal */}
      {isAdmin && (
        <UserManagementModal
          isOpen={userModalOpen}
          onClose={() => setUserModalOpen(false)}
          currentUsername={user?.username}
        />
      )}
    </div>
  );
}

function MetricCard({ title, value, danger }) {
  return (
    <div className="w-32 rounded-panel border border-hairline bg-raised px-4 py-2.5 shadow-panel">
      <div
        className={`text-2xl font-bold ${
          danger ? "text-severity-critical" : "text-accent"
        }`}
      >
        {value}
      </div>
      <div className="mt-1 text-[10px] uppercase tracking-widest text-ink-muted">
        {title}
      </div>
    </div>
  );
}
