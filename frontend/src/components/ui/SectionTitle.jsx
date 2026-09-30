export default function SectionTitle({
  children,
}) {
  return (
    <h3 className="mb-4 border-l-4 border-accent pl-3 text-sm font-semibold uppercase tracking-widest text-white">
      {children}
    </h3>
  );
}