// frontend/src/components/LogExplorer.jsx
import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { getLogs } from '../api/siem.js';
import { getTimeRange } from '../constants/timeRange.js';
import SeverityBadge from './SeverityBadge.jsx';
import Panel from './ui/Panel';
import PanelHeader from './ui/PanelHeader';
import StatusDot from './ui/StatusDot';
import LoadingSkeleton from './ui/LoadingSkeleton';
import EmptyState from './ui/EmptyState';
import ErrorState from './ui/ErrorState';
import {
  IconFileText,
  IconSearch,
  IconFilter,
  IconClose,
  IconChevronLeft,
  IconChevronRight,
} from './ui/Icons.jsx';

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
    accessorFn: (row) => row['@timestamp'],
    cell: (info) => (
      <span className="tabular font-mono text-xs text-ink-muted">
        {formatTime(info.getValue())}
      </span>
    ),
  },
  {
    id: 'severity',
    header: 'Severity',
    accessorFn: (row) => row['event.severity'],
    cell: (info) => <SeverityBadge severity={info.getValue()} />,
  },
  {
    id: 'source',
    header: 'Source',
    accessorFn: (row) => row['log.source'],
    cell: (info) => (
      <span className="font-mono text-xs uppercase text-ink-muted">
        {info.getValue() || '—'}
      </span>
    ),
  },
  {
    id: 'eventType',
    header: 'Event type',
    accessorFn: (row) => row['event.type'],
    cell: (info) => (
      <span className="font-mono text-xs text-ink-primary">
        {info.getValue() || '—'}
      </span>
    ),
  },
  {
    id: 'sourceIp',
    header: 'Source IP',
    accessorFn: (row) => row['source.ip'],
    cell: (info) => (
      <span className="font-mono text-xs text-ink-primary">
        {info.getValue() ?? '—'}
      </span>
    ),
  },
  {
    id: 'host',
    header: 'Host',
    accessorFn: (row) => row['host.name'],
    cell: (info) => (
      <span className="font-mono text-xs text-ink-muted">
        {info.getValue() ?? '—'}
      </span>
    ),
  },
  {
    id: 'user',
    header: 'User',
    accessorFn: (row) => row['user.name'],
    cell: (info) => (
      <span className="font-mono text-xs text-ink-muted">
        {info.getValue() ?? '—'}
      </span>
    ),
  },
];

export default function LogExplorer({
  ipFilter,
  onClearIpFilter,
  timeRange = '24h',
  autoRefresh = true,
}) {
  const activeRange = getTimeRange(timeRange);
  const [source, setSource] = useState('');
  const [severity, setSeverity] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const { data, isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ['logs', { source, severity, q, ipFilter, page, timeRange }],
    queryFn: () =>
      getLogs({
        source: source || undefined,
        severity: severity || undefined,
        source_ip: ipFilter || undefined,
        from: new Date(Date.now() - activeRange.ms).toISOString(),
        q: q || undefined,
        page,
        pageSize,
      }),
    refetchInterval: autoRefresh ? 30_000 : false,
    placeholderData: (prev) => prev,
  });

  const logs = data?.logs ?? [];
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

  function handleClearFilters() {
    setSource('');
    setSeverity('');
    setQ('');
    setPage(1);
    onClearIpFilter?.();
  }

  return (
    <Panel className="flex flex-col">
      <PanelHeader
        icon={<IconFileText className="h-5 w-5" />}
        title="Log Explorer"
        subtitle={`Search and investigate ingested events (${activeRange.fullLabel})`}
        right={
          <div className="flex items-center gap-3">
            {isFetching && !isLoading && (
              <span
                className="flex items-center gap-1.5 text-[11px] text-ink-muted"
                title="Updating logs..."
              >
                <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
                <span>Syncing</span>
              </span>
            )}
            <StatusDot
              color={total > 0 ? 'bg-green-500' : 'bg-ink-dim'}
              text={`${total.toLocaleString()} Events`}
            />
          </div>
        }
      />

      {/* Filter and Search Bar */}
      <div className="grid gap-3 sm:gap-4 border-b border-hairline bg-raised p-4 sm:p-5 lg:grid-cols-[1fr_180px_180px_auto]">
        <div className="relative">
          <input
            value={q}
            onChange={(e) => {
              setPage(1);
              setQ(e.target.value);
            }}
            placeholder="Search logs (e.g. 4625, root, admin)..."
            aria-label="Search logs"
            className="w-full rounded-xl border border-hairline bg-panel pl-10 pr-4 py-3 text-sm text-white placeholder:text-ink-muted focus:border-accent focus:outline-none"
          />
          <div className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none text-ink-muted">
            <IconSearch className="h-4 w-4" />
          </div>
        </div>

        <select
          value={source}
          onChange={(e) => {
            setPage(1);
            setSource(e.target.value);
          }}
          aria-label="Filter by source"
          className="rounded-xl border border-hairline bg-panel px-4 py-3 text-sm text-white focus:border-accent"
        >
          <option value="">All Sources</option>
          {SOURCES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        <select
          value={severity}
          onChange={(e) => {
            setPage(1);
            setSeverity(e.target.value);
          }}
          aria-label="Filter by severity"
          className="rounded-xl border border-hairline bg-panel px-4 py-3 text-sm text-white focus:border-accent"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        <button
          onClick={handleClearFilters}
          disabled={!filtersActive}
          aria-label="Clear all log filters"
          className="rounded-xl border border-hairline bg-panel px-5 py-3 text-white transition hover:border-accent disabled:opacity-40"
        >
          Clear
        </button>
      </div>

      {/* Active IP Filter Pill */}
      {ipFilter && (
        <div className="px-5 pt-4">
          <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/10 px-4 py-2 text-sm text-orange-400">
            <IconFilter className="h-3.5 w-3.5 shrink-0" />
            <span className="font-mono">{ipFilter}</span>
            <button
              onClick={onClearIpFilter}
              aria-label="Remove IP filter"
              className="font-bold transition hover:text-white p-0.5"
            >
              <IconClose className="h-3 w-3" />
            </button>
          </span>
        </div>
      )}

      {/* Table Content */}
      <div className="overflow-x-auto rounded-lg">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 z-10 bg-raised">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-hairline">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-ink-muted"
                  >
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext()
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {/* Initial Loading Skeleton */}
            {isLoading && logs.length === 0 && (
              <LoadingSkeleton variant="table" count={6} />
            )}

            {/* API Error State */}
            {!isLoading && isError && logs.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="px-5 py-12 text-center">
                  <ErrorState
                    title="Unable to load log events"
                    message="The SIEM API is temporarily unavailable."
                    onRetry={() => refetch()}
                  />
                </td>
              </tr>
            )}

            {/* Empty State: Filters returned no results */}
            {!isLoading && !isError && logs.length === 0 && filtersActive && (
              <tr>
                <td colSpan={columns.length} className="px-5 py-12 text-center">
                  <EmptyState
                    icon={<IconSearch className="h-6 w-6 text-ink-muted" />}
                    title="No logs match your filters"
                    description="No events found matching your search query, source, or severity filters."
                    action={
                      <button
                        onClick={handleClearFilters}
                        className="rounded-lg border border-hairline bg-panel px-4 py-2 font-mono text-xs text-accent hover:border-accent"
                      >
                        Reset All Filters
                      </button>
                    }
                  />
                </td>
              </tr>
            )}

            {/* Empty State: SIEM completely empty for active time window */}
            {!isLoading && !isError && logs.length === 0 && !filtersActive && (
              <tr>
                <td colSpan={columns.length} className="px-5 py-12 text-center">
                  <EmptyState
                    icon={<IconFileText className="h-6 w-6 text-ink-muted" />}
                    title="No logs indexed in this window"
                    description={`No events recorded in the ${activeRange.fullLabel.toLowerCase()}. Upload files or configure a Beat shipper to start streaming.`}
                  />
                </td>
              </tr>
            )}

            {/* Render Log Rows */}
            {logs.length > 0 &&
              table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className="border-b border-hairline/40 odd:bg-panel even:bg-raised/40 transition hover:bg-orange-500/5"
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-5 py-3">
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </td>
                  ))}
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-hairline bg-raised px-4 sm:px-6 py-3 sm:py-4">
        <span className="text-xs sm:text-sm font-mono text-ink-muted">
          Page {page} of {totalPages}
        </span>
        <div className="flex gap-2 sm:gap-3">
          <button
            disabled={page <= 1 || isLoading}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            aria-label="Previous page"
            className="inline-flex items-center gap-1.5 rounded-lg border border-hairline bg-panel px-3.5 sm:px-5 py-1.5 sm:py-2 text-xs sm:text-sm text-white transition hover:border-accent disabled:opacity-30"
          >
            <IconChevronLeft className="h-3.5 w-3.5 shrink-0" />
            <span>Previous</span>
          </button>
          <button
            disabled={page >= totalPages || isLoading}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            aria-label="Next page"
            className="inline-flex items-center gap-1.5 rounded-lg border border-hairline bg-panel px-3.5 sm:px-5 py-1.5 sm:py-2 text-xs sm:text-sm text-white transition hover:border-accent disabled:opacity-30"
          >
            <span>Next</span>
            <IconChevronRight className="h-3.5 w-3.5 shrink-0" />
          </button>
        </div>
      </div>
    </Panel>
  );
}
