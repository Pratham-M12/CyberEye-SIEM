// frontend/src/components/TopAttackers.jsx
import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

import { getTopAttackers } from '../api/siem.js';
import { getTimeRange } from '../constants/timeRange.js';
import Panel from './ui/Panel';
import PanelHeader from './ui/PanelHeader';
import StatusDot from './ui/StatusDot';
import LoadingSkeleton from './ui/LoadingSkeleton';
import EmptyState from './ui/EmptyState';
import ErrorState from './ui/ErrorState';

export default function TopAttackers({
  onSelectIp,
  selectedIp,
  timeRange = '24h',
  autoRefresh = true,
}) {
  const activeRange = getTimeRange(timeRange);

  const { data, isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ['alerts', 'top-attackers', timeRange],
    queryFn: () => getTopAttackers({ window: activeRange.id, limit: 8 }),
    refetchInterval: autoRefresh ? 30_000 : false,
    placeholderData: (prev) => prev,
  });

  const attackers = data?.attackers ?? [];

  return (
    <Panel className="flex h-full flex-col">
      <PanelHeader
        icon="🎯"
        title="Top Attackers"
        subtitle={`Most active source IPs (${activeRange.fullLabel})`}
        right={
          <div className="flex items-center gap-3">
            {isFetching && !isLoading && (
              <span
                className="flex items-center gap-1.5 text-[11px] text-ink-muted"
                title="Updating attackers..."
              >
                <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
                <span>Syncing</span>
              </span>
            )}
            {selectedIp ? (
              <button
                onClick={() => onSelectIp(null)}
                aria-label="Clear selected IP filter"
                className="rounded-md border border-accent px-3 py-1 text-xs font-medium text-accent transition hover:bg-accent hover:text-white"
              >
                Clear Filter
              </button>
            ) : (
              <StatusDot
                color={attackers.length > 0 ? 'bg-green-500' : 'bg-ink-dim'}
                text={`${attackers.length} Active`}
              />
            )}
          </div>
        }
      />

      <div className="flex-1 p-3.5 sm:p-6">
        {/* Initial loading skeleton */}
        {isLoading && attackers.length === 0 && (
          <LoadingSkeleton variant="bar-chart" count={6} />
        )}

        {/* API Error State */}
        {isError && attackers.length === 0 && (
          <ErrorState
            title="Unable to load attackers"
            message="The SIEM API is temporarily unavailable."
            onRetry={() => refetch()}
            className="h-[320px]"
          />
        )}

        {/* Clean Empty State */}
        {!isLoading && !isError && attackers.length === 0 && (
          <EmptyState
            icon="🎯"
            title="No attackers observed"
            description={`No high-frequency offending source IPs recorded in the ${activeRange.fullLabel.toLowerCase()}.`}
            className="h-[320px]"
          />
        )}

        {/* Non-destructive background error indicator if data exists */}
        {isError && attackers.length > 0 && (
          <div className="mb-3">
            <ErrorState
              compact
              message="Unable to refresh attacker data."
              onRetry={() => refetch()}
            />
          </div>
        )}

        {/* Chart Render */}
        {!isLoading && attackers.length > 0 && (
          <ResponsiveContainer width="100%" height={320}>
            <BarChart
              data={attackers}
              layout="vertical"
              margin={{
                top: 10,
                right: 15,
                left: 5,
                bottom: 5,
              }}
              onClick={(state) => {
                const ip = state?.activePayload?.[0]?.payload?.source_ip;
                if (ip) {
                  onSelectIp(ip === selectedIp ? null : ip);
                }
              }}
            >
              <CartesianGrid
                stroke="#555"
                strokeDasharray="3 3"
                horizontal={false}
              />

              <XAxis
                type="number"
                allowDecimals={false}
                stroke="#A2A2A2"
                tick={{
                  fontSize: 11,
                  fontFamily: 'JetBrains Mono',
                }}
              />

              <YAxis
                type="category"
                dataKey="source_ip"
                width={105}
                stroke="#A2A2A2"
                tick={{
                  fontSize: 11,
                  fontFamily: 'JetBrains Mono',
                }}
              />

              <Tooltip
                cursor={{
                  fill: 'rgba(255,90,31,.08)',
                }}
                contentStyle={{
                  background: '#303030',
                  border: '1px solid #555',
                  borderRadius: '8px',
                  color: '#fff',
                }}
              />

              <Bar
                dataKey="alert_count"
                radius={[0, 6, 6, 0]}
                cursor="pointer"
              >
                {attackers.map((entry) => (
                  <Cell
                    key={entry.source_ip}
                    fill={
                      entry.source_ip === selectedIp ? '#FF5A1F' : '#FB8C00'
                    }
                    fillOpacity={
                      selectedIp && entry.source_ip !== selectedIp ? 0.35 : 1
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Panel>
  );
}