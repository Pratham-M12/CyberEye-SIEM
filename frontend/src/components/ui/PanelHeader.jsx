export default function PanelHeader({
  icon,
  title,
  subtitle,
  right,
}) {
  return (
    <div className="flex items-center justify-between border-b border-hairline bg-raised px-5 py-4">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-accent text-lg font-bold text-white shadow">
          {icon}
        </div>
        <div>
          <h2 className="font-mono text-base font-semibold tracking-wide text-white">
            {title}
          </h2>
          {subtitle && (
            <p className="mt-0.5 text-xs text-ink-muted">
              {subtitle}
            </p>
          )}
        </div>
      </div>
      {right}
    </div>
  );
}