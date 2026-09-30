export default function Badge({
  children,
  color = "bg-accent",
}) {
  return (
    <span
      className={`${color} rounded-full px-3 py-1 text-xs font-semibold text-white`}
    >
      {children}
    </span>
  );
}