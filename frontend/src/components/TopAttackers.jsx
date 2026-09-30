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

import Panel from './ui/Panel';
import PanelHeader from './ui/PanelHeader';
import StatusDot from './ui/StatusDot';

export default function TopAttackers({ onSelectIp, selectedIp }) {
  const { data, isLoading } = useQuery({
    queryKey: ['alerts', 'top-attackers'],
    queryFn: () => getTopAttackers({ window: '24h', limit: 8 }),
    refetchInterval: 30000,
  });

  const attackers = data?.attackers ?? [];

  return (
    <Panel className="flex h-full flex-col">

      <PanelHeader
        icon="🎯"
        title="Top Attackers"
        subtitle="Most active source IPs (Last 24 Hours)"
        right={
          selectedIp ? (
            <button
              onClick={() => onSelectIp(null)}
              className="rounded-md border border-accent px-3 py-1 text-xs font-medium text-accent transition hover:bg-accent hover:text-white"
            >
              Clear Filter
            </button>
          ) : (
            <StatusDot
              color="bg-green-500"
              text={`${attackers.length} Active`}
            />
          )
        }
      />

      <div className="flex-1 p-6">

        {isLoading && (
          <div className="text-sm text-ink-muted">
            Loading attackers...
          </div>
        )}

        {!isLoading && attackers.length === 0 && (
          <div className="flex h-full items-center justify-center text-center">

            <div>

              <div className="mb-4 text-5xl">
                🎯
              </div>

              <p className="text-ink-secondary">
                No attacker activity detected.
              </p>

              <p className="mt-2 text-sm text-ink-muted">
                Alerts will appear here once detection rules trigger.
              </p>

            </div>

          </div>
        )}

        {!isLoading && attackers.length > 0 && (

          <ResponsiveContainer width="100%" height={320}>

            <BarChart
              data={attackers}
              layout="vertical"
              margin={{
                top: 10,
                right: 15,
                left: 15,
                bottom: 5,
              }}
              onClick={(state) => {
                const ip =
                  state?.activePayload?.[0]?.payload?.source_ip;

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
                width={120}
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
                      entry.source_ip === selectedIp
                        ? '#FF5A1F'
                        : '#FB8C00'
                    }
                    fillOpacity={
                      selectedIp &&
                      entry.source_ip !== selectedIp
                        ? 0.35
                        : 1
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