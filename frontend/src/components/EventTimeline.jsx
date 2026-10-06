// frontend/src/components/EventTimeline.jsx
import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

import { getTimeline } from '../api/siem.js';
import { getTimeRange } from '../constants/timeRange.js';
import Panel from './ui/Panel';
import PanelHeader from './ui/PanelHeader';
import LoadingSkeleton from './ui/LoadingSkeleton';
import EmptyState from './ui/EmptyState';
import ErrorState from './ui/ErrorState';
import { IconActivity, IconBarChart } from './ui/Icons.jsx';

const SOURCE_COLORS = {
  windows: '#4FA8E0',
  snort: '#E53935',
  nginx: '#FF5A1F',
  apache: '#FB8C00',
  syslog: '#9E9E9E',
};

function formatTick(ts) {
  return new Date(ts).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function EventTimeline({ timeRange = '24h', autoRefresh = true }) {
  const activeRange = getTimeRange(timeRange);

  const { data, isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ['stats', 'timeline', timeRange],
    queryFn: () =>
      getTimeline({ window: activeRange.id, interval: activeRange.interval }),
    refetchInterval: autoRefresh ? 30_000 : false,
    placeholderData: (prev) => prev,
  });

  const timeline = data?.timeline ?? [];

  const sources = Array.from(
    new Set(
      timeline.flatMap((point) =>
        Object.keys(point).filter((k) => k !== 'timestamp')
      )
    )
  );

  return (
    <Panel className="flex h-full flex-col">
      <PanelHeader
        icon={<IconActivity className="h-5 w-5" />}
        title="Event Timeline"
        subtitle={`Events in the ${activeRange.fullLabel.toLowerCase()}`}
        right={
          isFetching && !isLoading ? (
            <span
              className="flex items-center gap-1.5 text-[11px] text-ink-muted"
              title="Updating timeline..."
            >
              <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
              <span>Syncing</span>
            </span>
          ) : null
        }
      />

      <div className="flex-1 p-3.5 sm:p-6">
        {/* Initial loading skeleton */}
        {isLoading && timeline.length === 0 && (
          <LoadingSkeleton variant="chart" />
        )}

        {/* API Error State */}
        {isError && timeline.length === 0 && (
          <ErrorState
            title="Unable to load timeline"
            message="The SIEM API is temporarily unavailable."
            onRetry={() => refetch()}
            className="h-[320px]"
          />
        )}

        {/* Clean Empty State */}
        {!isLoading && !isError && timeline.length === 0 && (
          <EmptyState
            icon={<IconBarChart className="h-6 w-6 text-ink-muted" />}
            title="No events in this time range"
            description={`No log activity has been recorded in the ${activeRange.fullLabel.toLowerCase()}. Telemetry from Filebeat and Winlogbeat will chart here.`}
            className="h-[320px]"
          />
        )}

        {/* Non-destructive background error indicator if data exists */}
        {isError && timeline.length > 0 && (
          <div className="mb-3">
            <ErrorState
              compact
              message="Unable to refresh timeline data."
              onRetry={() => refetch()}
            />
          </div>
        )}

        {/* Chart Render */}
        {!isLoading && timeline.length > 0 && (
          <ResponsiveContainer width="100%" height={320}>
            <AreaChart
              data={timeline}
              margin={{
                top: 10,
                right: 10,
                left: -20,
                bottom: 5,
              }}
            >
              <defs>
                {sources.map((source) => (
                  <linearGradient
                    key={source}
                    id={`grad-${source}`}
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="5%"
                      stopColor={SOURCE_COLORS[source] ?? '#FF5A1F'}
                      stopOpacity={0.45}
                    />
                    <stop
                      offset="95%"
                      stopColor={SOURCE_COLORS[source] ?? '#FF5A1F'}
                      stopOpacity={0}
                    />
                  </linearGradient>
                ))}
              </defs>

              <CartesianGrid
                stroke="#555"
                strokeDasharray="3 3"
                vertical={false}
              />

              <XAxis
                dataKey="timestamp"
                tickFormatter={formatTick}
                stroke="#A2A2A2"
                tick={{
                  fontSize: 11,
                  fontFamily: 'JetBrains Mono',
                }}
              />

              <YAxis
                stroke="#A2A2A2"
                tick={{
                  fontSize: 11,
                  fontFamily: 'JetBrains Mono',
                }}
              />

              <Tooltip
                labelFormatter={formatTick}
                contentStyle={{
                  background: '#303030',
                  border: '1px solid #555',
                  borderRadius: '8px',
                  color: '#fff',
                }}
              />

              <Legend
                wrapperStyle={{
                  fontSize: 11,
                  fontFamily: 'JetBrains Mono',
                }}
              />

              {sources.map((source) => (
                <Area
                  key={source}
                  type="monotone"
                  dataKey={source}
                  stackId="1"
                  stroke={SOURCE_COLORS[source] ?? '#FF5A1F'}
                  fill={`url(#grad-${source})`}
                  strokeWidth={3}
                  dot={false}
                  activeDot={{
                    r: 5,
                  }}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </Panel>
  );
}