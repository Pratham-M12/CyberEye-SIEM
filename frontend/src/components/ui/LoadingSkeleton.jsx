export default function LoadingSkeleton({
  height = "h-4",
}) {
  return (
    <div
      className={`${height} w-full animate-pulse rounded bg-gray-600`}
    />
  );
}