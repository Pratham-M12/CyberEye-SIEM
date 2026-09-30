export default function StatusDot({
  color = "bg-green-500",
  text = "Online",
}) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={`h-2.5 w-2.5 rounded-full ${color}`}
      />
      <span className="text-xs text-ink-muted">
        {text}
      </span>
    </div>
  );
}