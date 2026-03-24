export default function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold ${
      ok ? "severity-low" : "severity-critical"
    }`}>
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-green-400" : "bg-red-400"}`} />
      {label}
    </span>
  );
}
