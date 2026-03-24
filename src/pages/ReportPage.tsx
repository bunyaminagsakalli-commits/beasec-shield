import { useState } from "react";
import ScanInput from "@/components/ScanInput";
import RiskGauge from "@/components/RiskGauge";
import SeverityBadge from "@/components/SeverityBadge";
import { performScan, type ScanResult } from "@/lib/scan-engine";
import { FileText, Download, Shield } from "lucide-react";

export default function ReportPage() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);

  const handleScan = (target: string) => {
    setLoading(true);
    setTimeout(() => {
      setResult(performScan(target));
      setLoading(false);
    }, 1500);
  };

  return (
    <div className="container px-4 py-8 pb-24 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Intelligence Report</h1>
          <p className="text-muted-foreground">Full aggregated security analysis</p>
        </div>
        <div className="p-2.5 rounded-lg bg-primary/10">
          <FileText className="h-5 w-5 text-primary" />
        </div>
      </div>

      <div className="max-w-2xl">
        <ScanInput onScan={handleScan} loading={loading} />
      </div>

      {result && !loading && (
        <div className="space-y-6 animate-fade-in-up">
          {/* Report Header */}
          <div className="glass-card p-6 cyber-glow">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <Shield className="h-6 w-6 text-primary" />
                <div>
                  <h2 className="text-xl font-bold">BEASEC Intelligence Report</h2>
                  <p className="text-xs text-muted-foreground font-mono">{result.target} — {new Date(result.scanDate).toLocaleString()}</p>
                </div>
              </div>
              <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary text-sm hover:bg-secondary/80 transition-colors">
                <Download className="h-4 w-4" /> Export
              </button>
            </div>

            <div className="grid md:grid-cols-4 gap-4">
              <RiskGauge score={result.overallScore} level={result.riskLevel} />
              <div className="md:col-span-3 grid grid-cols-2 gap-3">
                {[
                  { label: "Verdict", value: result.verdict },
                  { label: "Target Type", value: result.targetType.toUpperCase() },
                  { label: "SSL Grade", value: result.sslStatus.grade },
                  { label: "Malware", value: result.malwareStatus.detected ? "DETECTED" : "Clean" },
                  { label: "Blacklisted", value: result.blacklistStatus.listed ? `Yes (${result.blacklistStatus.sources.length})` : "No" },
                  { label: "Headers Score", value: `${result.securityHeaders.score}/100` },
                  { label: "Uptime", value: `${result.uptime.percentage.toFixed(2)}%` },
                  { label: "Software", value: result.softwareStatus.outdated ? "Outdated" : "Current" },
                ].map(item => (
                  <div key={item.label} className="p-3 rounded-lg bg-secondary/50">
                    <p className="text-xs text-muted-foreground">{item.label}</p>
                    <p className="font-semibold text-sm font-mono">{item.value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Source Evidence */}
          <div className="glass-card p-6 space-y-4">
            <h3 className="font-bold text-lg">Source-by-Source Evidence</h3>
            <div className="space-y-2">
              {result.sourceResults.map(s => (
                <div key={s.source} className="flex items-center justify-between p-4 rounded-lg bg-secondary/50 border border-border/50">
                  <div className="space-y-0.5">
                    <p className="font-semibold text-sm">{s.source}</p>
                    <p className="text-xs text-muted-foreground">{s.details}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-muted-foreground">{s.confidence}%</span>
                    <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${
                      s.status === 'clean' ? 'severity-low' : s.status === 'suspicious' ? 'severity-medium' : 'severity-critical'
                    }`}>{s.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Alerts & Recs */}
          <div className="grid lg:grid-cols-2 gap-4">
            <div className="glass-card p-6 space-y-3">
              <h3 className="font-bold">Alerts ({result.alerts.length})</h3>
              {result.alerts.map(a => (
                <div key={a.id} className="flex items-start gap-2 p-3 rounded-lg bg-secondary/50">
                  <SeverityBadge severity={a.severity} />
                  <div>
                    <p className="text-sm font-medium">{a.title}</p>
                    <p className="text-xs text-muted-foreground">{a.description}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="glass-card p-6 space-y-3">
              <h3 className="font-bold">Recommendations ({result.recommendations.length})</h3>
              {result.recommendations.map(r => (
                <div key={r.id} className="p-3 rounded-lg bg-secondary/50 space-y-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={r.priority} />
                    <span className="text-sm font-medium">{r.title}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{r.description}</p>
                  <p className="text-xs text-primary">→ {r.action}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Future module note */}
          <div className="glass-card p-6 border border-primary/20">
            <h3 className="font-bold text-sm text-primary mb-2">🔮 Future: Vulnerability Intelligence Module</h3>
            <p className="text-xs text-muted-foreground">
              Architecture supports OWASP Top 10, MITRE CWE, CVE/NVD, CISA KEV, and MITRE ATT&CK mapping. 
              Each finding will include severity, confidence, OWASP mapping, CWE classification, CVE exposure, and remediation guidance.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
