import { Bell, Filter } from "lucide-react";
import SeverityBadge from "@/components/SeverityBadge";
import type { AlertSeverity } from "@/lib/scan-engine";
import { useState } from "react";

const allAlerts = [
  { id: "1", severity: "critical" as AlertSeverity, title: "Malware Detected on example-malware.test", description: "Trojan.GenericKD detected in hosted scripts. Immediate remediation required.", time: "15 min ago", target: "example-malware.test" },
  { id: "2", severity: "critical" as AlertSeverity, title: "SSL Certificate Expired", description: "SSL certificate for example-malware.test has expired (Grade F).", time: "15 min ago", target: "example-malware.test" },
  { id: "3", severity: "critical" as AlertSeverity, title: "Blacklist Detection", description: "Target found on 3 blacklists: VirusTotal, URLhaus, Google Safe Browsing.", time: "15 min ago", target: "example-malware.test" },
  { id: "4", severity: "high" as AlertSeverity, title: "Phishing Infrastructure Suspected", description: "suspicious-shop.test flagged by PhishTank as possible phishing site.", time: "2 hr ago", target: "suspicious-shop.test" },
  { id: "5", severity: "medium" as AlertSeverity, title: "Outdated WordPress Installation", description: "WordPress 5.2 detected with multiple known vulnerabilities.", time: "2 hr ago", target: "suspicious-shop.test" },
  { id: "6", severity: "medium" as AlertSeverity, title: "Weak Security Headers", description: "Missing CSP and X-Frame-Options headers on suspicious-shop.test.", time: "2 hr ago", target: "suspicious-shop.test" },
  { id: "7", severity: "medium" as AlertSeverity, title: "Self-signed SSL Certificate", description: "192.168.1.1 uses a self-signed certificate (Grade C).", time: "3 hr ago", target: "192.168.1.1" },
  { id: "8", severity: "info" as AlertSeverity, title: "Clean Scan Complete", description: "google.com passed all security checks with no issues.", time: "2 min ago", target: "google.com" },
  { id: "9", severity: "info" as AlertSeverity, title: "DNS Resolution Healthy", description: "8.8.8.8 (Google DNS) is operating normally.", time: "1 hr ago", target: "8.8.8.8" },
];

const filters: AlertSeverity[] = ['critical', 'high', 'medium', 'info'];

export default function AlertsPage() {
  const [active, setActive] = useState<AlertSeverity | 'all'>('all');
  const filtered = active === 'all' ? allAlerts : allAlerts.filter(a => a.severity === active);

  return (
    <div className="container px-4 py-8 pb-24 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Alerts Center</h1>
          <p className="text-muted-foreground">{allAlerts.length} active alerts</p>
        </div>
        <div className="p-2.5 rounded-lg bg-primary/10">
          <Bell className="h-5 w-5 text-primary" />
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="h-4 w-4 text-muted-foreground" />
        <button onClick={() => setActive('all')} className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${active === 'all' ? 'bg-primary/15 text-primary' : 'bg-secondary text-muted-foreground hover:text-foreground'}`}>All</button>
        {filters.map(f => (
          <button key={f} onClick={() => setActive(f)} className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors capitalize ${active === f ? 'bg-primary/15 text-primary' : 'bg-secondary text-muted-foreground hover:text-foreground'}`}>{f}</button>
        ))}
      </div>

      {/* Alert list */}
      <div className="space-y-3">
        {filtered.map(a => (
          <div key={a.id} className="glass-card-hover p-5 space-y-2">
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-3">
                <SeverityBadge severity={a.severity} />
                <h3 className="font-semibold text-sm">{a.title}</h3>
              </div>
              <span className="text-xs text-muted-foreground whitespace-nowrap">{a.time}</span>
            </div>
            <p className="text-sm text-muted-foreground">{a.description}</p>
            <p className="text-xs font-mono text-primary">{a.target}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
