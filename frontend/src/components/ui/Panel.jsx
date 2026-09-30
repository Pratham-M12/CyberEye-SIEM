export default function Panel({
  children,
  className = "",
}) {
  return (
    <section
      className={`
        dashboard-card
        overflow-hidden
        rounded-panel
        bg-panel
        border
        border-hairline
        shadow-panel
        transition-all
        duration-300
        hover:shadow-raised
        ${className}
      `}
    >
      {children}
    </section>
  );
}