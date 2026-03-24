import { useState } from "react";
import { Search, Zap } from "lucide-react";
import { demoTargets } from "@/lib/scan-engine";

interface Props {
  onScan: (target: string) => void;
  loading?: boolean;
}

export default function ScanInput({ onScan, loading }: Props) {
  const [value, setValue] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (value.trim()) onScan(value.trim());
  };

  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder="Enter IP, domain, or URL..."
            className="w-full pl-10 pr-4 py-3 rounded-xl bg-secondary border border-border text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono text-sm"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !value.trim()}
          className="px-6 py-3 rounded-xl bg-primary text-primary-foreground font-semibold text-sm hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {loading ? (
            <div className="h-4 w-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
          ) : (
            <Zap className="h-4 w-4" />
          )}
          Scan
        </button>
      </form>

      <div className="flex flex-wrap gap-2">
        <span className="text-xs text-muted-foreground py-1">Try:</span>
        {demoTargets.map(t => (
          <button
            key={t.value}
            onClick={() => { setValue(t.value); onScan(t.value); }}
            className="text-xs px-3 py-1.5 rounded-lg bg-secondary/80 text-muted-foreground hover:text-foreground hover:bg-secondary transition-colors border border-border/50"
          >
            {t.label}
          </button>
        ))}
      </div>
    </div>
  );
}
