import { useState, useEffect, useMemo } from 'react';
import { useQuery, useQueryClient, useIsFetching } from '@tanstack/react-query';
import { getSummary } from './api/siem.js';
import { useAuth } from './context/AuthContext.jsx';
import LoginView from './components/LoginView.jsx';
import UserManagementModal from './components/UserManagementModal.jsx';
import DashboardControls from './components/DashboardControls.jsx';
import AlertQueue from './components/AlertQueue.jsx';
import EventTimeline from './components/EventTimeline.jsx';
import TopAttackers from './components/TopAttackers.jsx';
import LogExplorer from './components/LogExplorer.jsx';
import AlertDrawer from './components/AlertDrawer.jsx';
import UploadPanel from './components/UploadPanel.jsx';
import { DEFAULT_TIME_RANGE, getTimeRange } from './constants/timeRange.js';

export default function App() {
  const { user, isAuthenticated, logout, hasRole } = useAuth();
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [ipFilter, setIpFilter] = useState(null);
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [timeRange, setTimeRange] = useState(DEFAULT_TIME_RANGE);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastRefreshedAt, setLastRefreshedAt] = useState(() => new Date());
  const [refreshError, setRefreshError] = useState(false);

  const queryClient = useQueryClient();
  const fetchingCount = useIsFetching();
  const isRefreshing = fetchingCount > 0;

  const {
    data: summary,
    isLoading: isSummaryLoading,
    isError: isSummaryError,
  } = useQuery({
    queryKey: ['stats', 'summary'],
    queryFn: getSummary,
    enabled: isAuthenticated,
    refetchInterval: autoRefresh ? 30_000 : false,
    placeholderData: (prev) => prev,
  });

  useEffect(() => {
    if (summary) {
      setLastRefreshedAt(new Date());
    }
  }, [summary]);

  const handleManualRefresh = async () => {
    try {
      setRefreshError(false);
      await queryClient.refetchQueries({ type: 'active' });
      setLastRefreshedAt(new Date());
    } catch (err) {
      console.error('Manual refresh failed:', err);
      setRefreshError(true);
    }
  };

  // Derive active range metadata & event count
  const activeRange = getTimeRange(timeRange);
  const timelineData = queryClient.getQueryData(['stats', 'timeline', timeRange]);
  const timelineEventCount = useMemo(() => {
    if (!timelineData?.timeline || !Array.isArray(timelineData.timeline)) return null;
    return timelineData.timeline.reduce((total, pt) => {
      const ptSum = Object.entries(pt).reduce((sum, [key, val]) => {
        if (key !== 'timestamp' && typeof val === 'number') return sum + val;
        return sum;
      }, 0);
      return total + ptSum;
    }, 0);
  }, [timelineData, timeRange]);

  const totalEventsDisplay = useMemo(() => {
    if (timeRange === '24h') {
      return summary?.events_last_24h != null
        ? summary.events_last_24h.toLocaleString()
        : '—';
    }
    if (timelineEventCount != null) {
      return timelineEventCount.toLocaleString();
    }
    return summary?.events_last_24h != null
      ? summary.events_last_24h.toLocaleString()
      : '—';
  }, [timeRange, summary?.events_last_24h, timelineEventCount]);

  const eventsMetricTitle =
    timeRange === '24h'
      ? 'TOTAL EVENTS'
      : `EVENTS (${activeRange.label.toUpperCase()})`;

  // If unauthenticated, present secure CyberEye login interface
  if (!isAuthenticated) {
    return <LoginView />;
  }

  const role = user?.role?.toUpperCase() || 'USER';
  const isAdmin = hasRole('admin');

  return (
    <div className="min-h-screen bg-void">
      <header className="border-b border-hairline bg-panel shadow-panel">
        <div className="mx-auto flex max-w-[1700px] flex-wrap items-center justify-between gap-4 px-4 sm:px-8 py-3 sm:py-4">
          {/* Logo & Platform Info */}
          <div className="flex items-center gap-3 sm:gap-4">
            <div className="flex h-11 w-11 sm:h-12 sm:w-12 items-center justify-center rounded-panel bg-accent text-xl font-bold text-white shadow">
              C
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-semibold tracking-wide text-white">
                CyberEye SIEM
              </h1>
              <p className="text-xs text-ink-secondary">
                Enterprise Threat Monitoring Dashboard
              </p>
            </div>
          </div>

          {/* Metric Cards */}
          <div className="flex flex-wrap items-center gap-2 sm:gap-3 w-full sm:w-auto">
            <MetricCard
              title={eventsMetricTitle}
              value={totalEventsDisplay}
              loading={isSummaryLoading && !summary}
            />
            <MetricCard
              title="OPEN ALERTS"
              value={
                summary?.open_alerts != null
                  ? summary.open_alerts.toLocaleString()
                  : '—'
              }
              loading={isSummaryLoading && !summary}
            />
            <MetricCard
              title="CRITICAL"
              value={
                summary?.open_critical_alerts != null
                  ? summary.open_critical_alerts.toLocaleString()
                  : '—'
              }
              loading={isSummaryLoading && !summary}
              danger
            />
          </div>

          {/* Operator Profile, Role Badge & Session Controls */}
          <div className="flex items-center gap-3 sm:border-l sm:border-hairline sm:pl-4">
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

      {/* Global Dashboard Controls (Phase 9.2A) */}
      <DashboardControls
        timeRange={timeRange}
        onTimeRangeChange={setTimeRange}
        autoRefresh={autoRefresh}
        onToggleAutoRefresh={() => setAutoRefresh((prev) => !prev)}
        onManualRefresh={handleManualRefresh}
        isRefreshing={isRefreshing}
        lastUpdated={lastRefreshedAt}
        hasError={refreshError || (isSummaryError && !isSummaryLoading)}
        onClearError={() => setRefreshError(false)}
      />

      <main className="mx-auto grid max-w-[1700px] grid-cols-1 gap-4 p-4 sm:p-6 lg:p-8 lg:grid-cols-[380px_1fr]">
        <div className="max-h-[500px] lg:max-h-none lg:row-span-2 lg:h-[calc(100vh-8rem)]">
          <AlertQueue
            timeRange={timeRange}
            autoRefresh={autoRefresh}
            onSelectAlert={setSelectedAlertId}
            selectedAlertId={selectedAlertId}
          />
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <EventTimeline timeRange={timeRange} autoRefresh={autoRefresh} />
          <TopAttackers
            timeRange={timeRange}
            autoRefresh={autoRefresh}
            onSelectIp={setIpFilter}
            selectedIp={ipFilter}
          />
        </div>

        <div className="space-y-4 xl:col-span-1">
          <UploadPanel />
          <LogExplorer
            timeRange={timeRange}
            autoRefresh={autoRefresh}
            ipFilter={ipFilter}
            onClearIpFilter={() => setIpFilter(null)}
          />
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

function MetricCard({ title, value, danger, loading }) {
  return (
    <div
      className="flex-1 min-w-[96px] sm:w-32 sm:flex-initial rounded-panel border border-hairline bg-raised px-3 sm:px-4 py-2 sm:py-2.5 shadow-panel min-h-[66px] flex flex-col justify-center"
      role="region"
      aria-label={title}
    >
      {loading ? (
        <div className="h-7 flex items-center" aria-busy="true">
          <div className="h-6 w-16 animate-pulse rounded bg-hairline/60" />
        </div>
      ) : (
        <div
          className={`text-2xl font-bold leading-tight tabular font-mono ${
            danger ? "text-severity-critical" : "text-accent"
          }`}
        >
          {value}
        </div>
      )}
      <div className="mt-1 text-[10px] uppercase tracking-widest text-ink-muted">
        {title}
      </div>
    </div>
  );
}
