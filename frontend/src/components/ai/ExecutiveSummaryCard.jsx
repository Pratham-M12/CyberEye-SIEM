export default function ExecutiveSummaryCard({ summary }) {
  return (
    <div className="rounded-xl border border-hairline bg-raised p-5">
      <p className="mb-4 text-xs uppercase tracking-widest text-ink-muted">
        Executive Summary
      </p>
      <p className="leading-7 text-white">
        {summary}
      </p>
    </div>
  );
}