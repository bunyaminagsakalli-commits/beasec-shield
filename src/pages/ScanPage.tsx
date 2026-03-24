import { useState, useCallback } from "react";
import { Shield, Globe, Lock, Bug, AlertTriangle, Server, Clock, CheckCircle, XCircle } from "lucide-react";
import ScanInput from "@/components/ScanInput";
import RiskGauge from "@/components/RiskGauge";
import SeverityBadge from "@/components/SeverityBadge";
import StatusPill from "@/components/StatusPill";
import { performScan, type ScanResult } from "@/lib/scan-engine";

export default function ScanPage() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [progress, setProgress] = useState(0);

  const handleScan = useCallback((target: string) => {
    setLoading(true);
    setResult(null);
    setProgress(0);

    const interval = setInterval(() => {
      setProgress(p => {
        if (p >= 95) { clearInterval(interval); return 95; }
        return p + Math.random() * 15;
      });
    }, 200);

    setTimeout(() => {
      clearInterval(interval);
      setProgress(100);
      setResult(performScan(target));
      setLoading(false);
    }, 2200);
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

      {/* Progress */}
      {loading && (
        <div className="max-w-2xl mx-auto glass-card p-6 space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Scanning target...</span>
            <span className="font-mono text-primary">{Math.round(progress)}%</span>
          </div>
          <div className="h-2 rounded-full bg-secondary overflow-hidden">
            <div className="h-full rounded-full bg-primary transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
          <div className="flex flex-wrap gap-2">
            {['VirusTotal', 'AbuseIPDB', 'Shodan', 'URLhaus', 'OTX'].map((s, i) => (
              <span key={s} className={`text-xs px-2 py-1 rounded bg-secondary ${progress > i * 18 ? 'text-primary' : 'text-muted-foreground'} transition-colors`}>
                {progress > i * 18 ? '✓' : '○'} {s}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div className="space-y-6 animate-fade-in-up">
          {/* Summary row */}
          <div className="grid md:grid-cols-3 gap-4">
            <RiskGauge score={result.overallScore} level={result.riskLevel} />

            <div className="glass-card p-6 space-y-4 md:col-span-2">
              <div className="flex items-center justify-between">
                <h2 className="font-bold text-lg">Scan Summary</h2>
                <StatusPill ok={result.verdict === 'Clean'} label={result.verdict} />
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div><span className="text-muted-foreground">Target:</span> <span className="font-mono">{result.target}</span></div>
                <div><span className="text-muted-foreground">Type:</span> <span className="capitalize">{result.targetType}</span></div>
                <div><span className="text-muted-foreground">Scan Date:</span> <span className="font-mono text-xs">{new Date(result.scanDate).toLocaleString()}</span></div>
                {result.threatType && <div><span className="text-muted-foreground">Threat:</span> <span className="text-red-400">{result.threatType}</span></div>}
              </div>
            </div>
          </div>

          {/* Detail cards */}
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <DetailCard icon={Lock} title="SSL Certificate" ok={result.sslStatus.valid}
              items={[`Grade: ${result.sslStatus.grade}`, `Issuer: ${result.sslStatus.issuer}`, `Expiry: ${result.sslStatus.expiry}`]} />
            <DetailCard icon={Bug} title="Malware Status" ok={!result.malwareStatus.detected}
              items={[result.malwareStatus.details]} />
            <DetailCard icon={AlertTriangle} title="Blacklist Status" ok={!result.blacklistStatus.listed}
              items={result.blacklistStatus.listed ? result.blacklistStatus.sources : ['Not listed on any blacklist']} />
            <DetailCard icon={Shield} title="Security Headers" ok={result.securityHeaders.score >= 70}
              items={[`Score: ${result.securityHeaders.score}/100`, ...result.securityHeaders.missing.map(h => `Missing: ${h}`), ...result.securityHeaders.present.map(h => `✓ ${h}`)]} />
            <DetailCard icon={Clock} title="Uptime" ok={result.uptime.percentage > 95}
              items={[`${result.uptime.percentage.toFixed(2)}% uptime`]} />
            <DetailCard icon={Server} title="Software" ok={!result.softwareStatus.outdated}
              items={[result.softwareStatus.details]} />
          </div>

          {/* Source results */}
          <div className="glass-card p-6 space-y-4">
            <h3 className="font-bold flex items-center gap-2"><Globe className="h-4 w-4 text-primary" /> Intelligence Sources</h3>
            <div className="grid sm:grid-cols-2 gap-3">
              {result.sourceResults.map(s => (
                <div key={s.source} className="flex items-center justify-between p-3 rounded-lg bg-secondary/50 border border-border/50">
                  <div>
                    <span className="font-medium text-sm">{s.source}</span>
                    <p className="text-xs text-muted-foreground">{s.details}</p>
                  </div>
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                    s.status === 'clean' ? 'severity-low' : s.status === 'suspicious' ? 'severity-medium' : 'severity-critical'
                  }`}>{s.status}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Alerts */}
          <div className="glass-card p-6 space-y-4">
            <h3 className="font-bold">Alerts</h3>
            <div className="space-y-2">
              {result.alerts.map(a => (
                <div key={a.id} className="flex items-start gap-3 p-3 rounded-lg bg-secondary/50">
                  <SeverityBadge severity={a.severity} />
                  <div>
                    <p className="font-medium text-sm">{a.title}</p>
                    <p className="text-xs text-muted-foreground">{a.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recommendations */}
          <div className="glass-card p-6 space-y-4">
            <h3 className="font-bold">Recommendations</h3>
            <div className="space-y-2">
              {result.recommendations.map(r => (
                <div key={r.id} className="p-4 rounded-lg bg-secondary/50 border border-border/50 space-y-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={r.priority} />
                    <span className="font-semibold text-sm">{r.title}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{r.description}</p>
                  <p className="text-xs text-primary">→ {r.action}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailCard({ icon: Icon, title, ok, items }: { icon: any; title: string; ok: boolean; items: string[] }) {
  return (
    <div className="glass-card-hover p-5 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-primary" />
          <span className="font-semibold text-sm">{title}</span>
        </div>
        {ok ? <CheckCircle className="h-4 w-4 text-green-400" /> : <XCircle className="h-4 w-4 text-red-400" />}
      </div>
      <div className="space-y-1">
        {items.map((item, i) => (
          <p key={i} className="text-xs text-muted-foreground">{item}</p>
        ))}
      </div>
    </div>
  );
}
