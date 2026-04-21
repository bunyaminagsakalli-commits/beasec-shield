import { useState, useCallback } from "react";
import { Shield, Globe, AlertTriangle, CheckCircle, XCircle, Activity } from "lucide-react";
import ScanInput from "@/components/ScanInput";
import RiskGauge from "@/components/RiskGauge";
import StatusPill from "@/components/StatusPill";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

interface VTScanResult {
  target: string;
  targetType: "ip" | "domain" | "url";
  scanDate: string;
  score: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  verdict: "Clean" | "Suspicious" | "Malicious" | "High Risk";
  stats: { malicious: number; suspicious: number; harmless: number; undetected: number; total: number };
  reputation: number;
  topThreats: { name: string; count: number }[];
  engineFindings: { engine: string; category: string; result: string | null }[];
  lastAnalysisDate: string | null;
  country: string | null;
  asOwner: string | null;
  network: string | null;
  categories: Record<string, string> | null;
}

export default function ScanPage() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VTScanResult | null>(null);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const handleScan = useCallback(async (target: string) => {
    setLoading(true);
    setResult(null);
    setError(null);
    setProgress(0);

    const interval = setInterval(() => {
      setProgress(p => (p >= 92 ? 92 : p + Math.random() * 12));
    }, 250);

    try {
      const { data, error: fnError } = await supabase.functions.invoke("virustotal-scan", {
        body: { target },
      });
      clearInterval(interval);

      if (fnError) throw fnError;
      if ((data as any)?.error) throw new Error((data as any).error);

      setProgress(100);
      setResult(data as VTScanResult);
    } catch (e: any) {
      clearInterval(interval);
      setProgress(0);
      const msg = e?.message || "Scan failed";
      setError(msg);
      toast.error("Scan failed", { description: msg });
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div className="container px-4 py-8 pb-24 space-y-8">
      <div className="max-w-3xl mx-auto space-y-2 text-center">
        <h1 className="text-3xl font-bold">Universal Scanner</h1>
        <p className="text-muted-foreground">Enter an IP address, domain, or URL to analyze</p>
      </div>

      <div className="max-w-2xl mx-auto">
        <ScanInput onScan={handleScan} loading={loading} />
      </div>

      {error && !loading && (
        <div className="max-w-2xl mx-auto glass-card p-4 border border-red-500/30">
          <p className="text-sm text-red-400 font-medium">Error: {error}</p>
        </div>
      )}

      {/* Progress */}
      {loading && (
        <div className="max-w-2xl mx-auto glass-card p-6 space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Querying VirusTotal intelligence...</span>
            <span className="font-mono text-primary">{Math.round(progress)}%</span>
          </div>
          <div className="h-2 rounded-full bg-secondary overflow-hidden">
            <div className="h-full rounded-full bg-primary transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Activity className="h-3 w-3 animate-pulse text-primary" />
            Aggregating engine results from 70+ antivirus & URL scanners
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div className="space-y-6 animate-fade-in-up">
          {/* Summary row */}
          <div className="grid md:grid-cols-3 gap-4">
            <RiskGauge score={result.score} level={result.riskLevel} />

            <div className="glass-card p-6 space-y-4 md:col-span-2">
              <div className="flex items-center justify-between">
                <h2 className="font-bold text-lg">Scan Summary</h2>
                <StatusPill ok={result.verdict === 'Clean'} label={result.verdict} />
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div><span className="text-muted-foreground">Target:</span> <span className="font-mono">{result.target}</span></div>
                <div><span className="text-muted-foreground">Type:</span> <span className="capitalize">{result.targetType}</span></div>
                <div><span className="text-muted-foreground">Scan Date:</span> <span className="font-mono text-xs">{new Date(result.scanDate).toLocaleString()}</span></div>
                {result.lastAnalysisDate && (
                  <div><span className="text-muted-foreground">Last analysis:</span> <span className="font-mono text-xs">{new Date(result.lastAnalysisDate).toLocaleString()}</span></div>
                )}
                {result.country && <div><span className="text-muted-foreground">Country:</span> <span>{result.country}</span></div>}
                {result.asOwner && <div><span className="text-muted-foreground">AS Owner:</span> <span className="text-xs">{result.asOwner}</span></div>}
                {result.network && <div><span className="text-muted-foreground">Network:</span> <span className="font-mono text-xs">{result.network}</span></div>}
                <div><span className="text-muted-foreground">Reputation:</span> <span className={result.reputation < 0 ? "text-red-400" : "text-green-400"}>{result.reputation}</span></div>
              </div>
            </div>
          </div>

          {/* Detection stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <StatCard label="Malicious" value={result.stats.malicious} accent="text-red-400" icon={XCircle} />
            <StatCard label="Suspicious" value={result.stats.suspicious} accent="text-yellow-400" icon={AlertTriangle} />
            <StatCard label="Harmless" value={result.stats.harmless} accent="text-green-400" icon={CheckCircle} />
            <StatCard label="Undetected" value={result.stats.undetected} accent="text-muted-foreground" icon={Shield} />
          </div>

          {/* Threat categories */}
          {result.topThreats.length > 0 && (
            <div className="glass-card p-6 space-y-4">
              <h3 className="font-bold flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-400" /> Threat Categories
              </h3>
              <div className="flex flex-wrap gap-2">
                {result.topThreats.map(t => (
                  <span key={t.name} className="px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs font-mono text-red-300">
                    {t.name} <span className="opacity-60">×{t.count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Categories from VT */}
          {result.categories && Object.keys(result.categories).length > 0 && (
            <div className="glass-card p-6 space-y-4">
              <h3 className="font-bold flex items-center gap-2">
                <Globe className="h-4 w-4 text-primary" /> Site Categories
              </h3>
              <div className="grid sm:grid-cols-2 gap-2">
                {Object.entries(result.categories).map(([source, cat]) => (
                  <div key={source} className="flex justify-between text-xs p-2 rounded bg-secondary/50">
                    <span className="text-muted-foreground">{source}</span>
                    <span className="font-medium">{cat}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Engine findings */}
          <div className="glass-card p-6 space-y-4">
            <h3 className="font-bold flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" /> Engine Detections
              <span className="text-xs text-muted-foreground font-normal">
                ({result.engineFindings.length} of {result.stats.total} engines flagged)
              </span>
            </h3>
            {result.engineFindings.length === 0 ? (
              <div className="flex items-center gap-2 text-sm text-green-400">
                <CheckCircle className="h-4 w-4" />
                No engine flagged this target as malicious or suspicious.
              </div>
            ) : (
              <div className="grid sm:grid-cols-2 gap-2 max-h-96 overflow-y-auto">
                {result.engineFindings.map(f => (
                  <div key={f.engine} className="flex items-center justify-between p-3 rounded-lg bg-secondary/50 border border-border/50">
                    <div className="min-w-0">
                      <p className="font-medium text-sm truncate">{f.engine}</p>
                      {f.result && <p className="text-xs text-muted-foreground truncate font-mono">{f.result}</p>}
                    </div>
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ml-2 shrink-0 ${
                      f.category === 'malicious' ? 'severity-critical' : 'severity-medium'
                    }`}>{f.category}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, accent, icon: Icon }: { label: string; value: number; accent: string; icon: any }) {
  return (
    <div className="glass-card p-5 space-y-2">
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${accent}`} />
        <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      </div>
      <div className={`text-3xl font-bold ${accent}`}>{value}</div>
    </div>
  );
}
