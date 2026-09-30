import { useState } from "react";

export default function JsonViewer({ data }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="rounded-md border border-hairline">
      <button
        onClick={() => setOpen(!open)}
        className="w-full border-b border-hairline px-3 py-2 text-left font-mono text-xs"
      >
        {open ? "Hide Raw JSON" : "Show Raw JSON"}
      </button>

      {open && (
        <pre className="overflow-auto p-4 text-xs text-ink-primary">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
}