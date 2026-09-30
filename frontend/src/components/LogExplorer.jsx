// frontend/src/components/LogExplorer.jsx

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { flexRender, getCoreRowModel, useReactTable } from '@tanstack/react-table';
import { getLogs } from '../api/siem.js';
import SeverityBadge from './SeverityBadge.jsx';
import Panel from "./ui/Panel";
import PanelHeader from "./ui/PanelHeader";
import StatusDot from "./ui/StatusDot";

const SOURCES = ['windows', 'snort', 'nginx', 'apache', 'syslog'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

const columns = [
  {
    header: 'Time',
    id: '@timestamp',
    accessorFn: row => row['@timestamp'],
    cell: (info) => (
      <span className="tabular font-mono text-xs text-ink-muted">{formatTime(info.getValue())}</span>
    ),
  },
  {
    id: 'severity',
    header: 'Severity',
    accessorFn: row => row['event.severity'],
    cell: (info) => {
      console.log("Severity value:", info.getValue());
      return <SeverityBadge severity={info.getValue()} />;
    },
  },
  {
    id: 'source',
    header: 'Source',
    accessorFn: row => row['log.source'],
    cell: (info) => (
      <span className="font-mono text-xs uppercase text-ink-muted">{info.getValue()}</span>
    ),
  },
  {
    id: 'eventType',
    header: 'Event type',
    accessorFn: row => row['event.type'],
    cell: (info) => <span className="font-mono text-xs text-ink-primary">{info.getValue()}</span>,
  },
  {
    id: 'sourceIp',
    header: 'Source IP',
    accessorFn: row => row['source.ip'],
    cell: (info) => <span className="font-mono text-xs text-ink-primary">{info.getValue() ?? '—'}</span>,
  },
  {
    id: 'host',
    header: 'Host',
    accessorFn: row => row['host.name'],
    cell: (info) => <span className="font-mono text-xs text-ink-muted">{info.getValue() ?? '—'}</span>,
  },
  {
    id: 'user',
    header: 'User',
    accessorFn: row => row['user.name'],
    cell: (info) => <span className="font-mono text-xs text-ink-muted">{info.getValue() ?? '—'}</span>,
  },
];

export default function LogExplorer({ ipFilter, onClearIpFilter }) {
  const [source, setSource] = useState('');
  const [severity, setSeverity] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const { data, isLoading } = useQuery({
    queryKey: ['logs', { source, severity, q, ipFilter, page }],
    queryFn: () =>
      getLogs({
        source: source || undefined,
        severity: severity || undefined,
        source_ip: ipFilter || undefined,
        q: q || undefined,
        page,
        pageSize,
      }),
    refetchInterval: 30_000,
  });

  const logs = data?.logs ?? [];
  console.log("FIRST LOG:", logs[0]);
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const table = useReactTable({
    data: logs,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  const filtersActive = useMemo(
    () => Boolean(source || severity || q || ipFilter),
    [source, severity, q, ipFilter]
  );

  return (
    <Panel className="flex flex-col">
      <PanelHeader
          icon="📜"
          title="Log Explorer"
          subtitle="Search and investigate ingested events"
          right={
              <StatusDot
                  color="bg-green-500"
                  text={`${total.toLocaleString()} Events`}
              />
          }
      />

      <div className="grid gap-4 border-b border-hairline bg-raised p-5 lg:grid-cols-[1fr_180px_180px_auto]">

          <input
              value={q}
              onChange={(e)=>{
                  setPage(1);
                  setQ(e.target.value);
              }}
              placeholder="🔍 Search logs..."
              className="rounded-xl border border-hairline bg-panel px-4 py-3 text-sm text-white placeholder:text-ink-muted focus:border-accent focus:outline-none"
          />

          <select
              value={source}
              onChange={(e)=>{
                  setPage(1);
                  setSource(e.target.value);
              }}
              className="rounded-xl border border-hairline bg-panel px-4 py-3 text-sm text-white focus:border-accent"
          >
              <option value="">All Sources</option>

              {SOURCES.map((s)=>(
                  <option key={s} value={s}>
                      {s}
                  </option>
              ))}

          </select>

          <select
              value={severity}
              onChange={(e)=>{
                  setPage(1);
                  setSeverity(e.target.value);
              }}
              className="rounded-xl border border-hairline bg-panel px-4 py-3 text-sm text-white focus:border-accent"
          >
              <option value="">All Severities</option>

              {SEVERITIES.map((s)=>(
                  <option key={s} value={s}>
                      {s}
                  </option>
              ))}

          </select>

          <button
              onClick={()=>{
                  setSource("");
                  setSeverity("");
                  setQ("");
                  setPage(1);
                  onClearIpFilter?.();
              }}
              className="rounded-xl border border-hairline bg-panel px-5 py-3 text-white transition hover:border-accent"
          >
              Clear
          </button>

      </div>

      {ipFilter && (
      <div className="px-5 pt-4">
        <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/10 px-4 py-2 text-sm text-orange-400">
          🟧 {ipFilter}

          <button
            onClick={onClearIpFilter}
            className="font-bold transition hover:text-white"
          >
            ×
          </button>
        </span>
      </div>
    )}

      <div className="overflow-auto rounded-lg">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 z-10 bg-raised">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-hairline">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-ink-muted"
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={columns.length} className="px-5 py-12 text-center">
                  <div className="flex flex-col items-center gap-3">
                    <div className="h-8 w-8 animate-spin rounded-full border-4 border-orange-500 border-t-transparent" />
                    <p className="text-sm text-ink-muted">
                      Loading events...
                    </p>
                  </div>
                </td>
              </tr>
            )}

            {!isLoading && logs.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="px-5 py-14 text-center">
                  <div className="flex flex-col items-center">
                    <div className="mb-3 text-5xl">📭</div>
                    <h3 className="text-lg font-semibold text-white">
                      No matching events
                    </h3>
                    <p className="mt-2 text-sm text-ink-muted">
                      Try changing your filters or search query.
                    </p>
                  </div>
                </td>
              </tr>
            )}

            {!isLoading &&
              table.getRowModel().rows.map((row) => (
                <tr key={row.id} className="border-b border-hairline/40 odd:bg-panel even:bg-raised/40 transition hover:bg-orange-500/5">
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-5 py-3">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between border-t border-hairline bg-raised px-6 py-4">
      <span className="text-sm text-ink-muted">
      Page {page} of {totalPages}
      </span>
      <div className="flex gap-3">
      <button
      disabled={page<=1}
      onClick={()=>setPage((p)=>Math.max(1,p-1))}
      className="rounded-lg border border-hairline bg-panel px-5 py-2 text-white transition hover:border-accent disabled:opacity-30"
      >
      ◀ Previous
      </button>
      <button
      disabled={page>=totalPages}
      onClick={()=>setPage((p)=>Math.min(totalPages,p+1))}
      className="rounded-lg border border-hairline bg-panel px-5 py-2 text-white transition hover:border-accent disabled:opacity-30"
      >
      Next ▶
      </button>
      </div>
      </div>
    </Panel>
  );
}
