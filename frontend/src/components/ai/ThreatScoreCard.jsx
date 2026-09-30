export default function ThreatScoreCard({ score = 92 }) {
  const color =
    score >= 90
      ? "bg-red-500"
      : score >= 70
      ? "bg-orange-500"
      : "bg-green-500";

  return (
    <div className="rounded-xl border border-hairline bg-raised p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-widest text-ink-muted">
            Threat Score
          </p>
          <h2 className="mt-2 text-4xl font-bold text-white">
            {score}
          </h2>
          <p className="text-sm text-ink-muted">
            /100
          </p>
        </div>
        <div className="h-24 w-3 rounded-full bg-panel overflow-hidden">
          <div
            className={`${color} w-full transition-all`}
            style={{ height: `${score}%` }}
          />
        </div>
      </div>
    </div>
  );
}