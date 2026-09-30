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

import Panel from './ui/Panel';
import PanelHeader from './ui/PanelHeader';

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

export default function EventTimeline() {
  const { data, isLoading } = useQuery({
    queryKey: ['stats', 'timeline'],
    queryFn: () => getTimeline({ window: '24h', interval: '1h' }),
    refetchInterval: 30000,
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
        icon="📈"
        title="Event Timeline"
        subtitle="Events in the last 24 hours"
      />

      <div className="flex-1 p-6">

        {isLoading && (
          <div className="text-sm text-ink-muted">
            Loading timeline...
          </div>
        )}

        {!isLoading && timeline.length === 0 && (
          <div className="flex h-full items-center justify-center text-center">

            <div>

              <div className="mb-4 text-5xl">
                📊
              </div>

              <p className="text-ink-secondary">
                No events indexed yet.
              </p>

              <p className="mt-2 text-sm text-ink-muted">
                Upload logs or wait for the detection engine.
              </p>

            </div>

          </div>
        )}

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