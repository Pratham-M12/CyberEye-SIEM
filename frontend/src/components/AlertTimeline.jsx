function formatTimestamp(ts) {
  return new Date(ts).toLocaleString();
}

const COLORS = {
  created: "bg-accent",
  acknowledged: "bg-yellow-500",
  closed: "bg-red-500",
  open: "bg-green-500",
};

export default function AlertTimeline({ history = [] }) {
  if (!history.length) {
    return (
      <p className="text-sm text-ink-muted">
        No lifecycle events available.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      {history.map((event, index) => (
        <div
          key={index}
          className="flex gap-3"
        >
          <div className="flex flex-col items-center">
            <div
              className={`h-3 w-3 rounded-full ${
                COLORS[event.action] || "bg-gray-500"
              }`}
            />

            {index !== history.length - 1 && (
              <div className="mt-1 h-10 w-px bg-hairline" />
            )}
          </div>

          <div className="flex-1">
            <p className="font-mono text-sm capitalize text-ink-primary">
              {event.action}
            </p>

            <p className="text-xs text-ink-muted">
              {event.by}
            </p>

            <p className="text-xs text-ink-dim">
              {formatTimestamp(event.timestamp)}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}