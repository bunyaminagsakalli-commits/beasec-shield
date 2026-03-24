import { Shield, AlertTriangle, Globe, Activity, TrendingUp, Bug, Lock, Server } from "lucide-react";

const stats = [
  { label: "Total Scans", value: "1,247", icon: Globe, change: "+12%" },
  { label: "Threats Detected", value: "23", icon: Bug, change: "+3" },
  { label: "Active Alerts", value: "8", icon: AlertTriangle, change: "-2" },
  { label: "Protected Assets", value: "156", icon: Shield, change: "+18" },
];

const recentScans = [
  { target: "google.com", type: "domain", risk: "Low", score: 5, time: "2 min ago" },
  { target: "example-malware.test", type: "domain", risk: "Critical", score: 92, time: "15 min ago" },
  { target: "8.8.8.8", type: "ip", risk: "Low", score: 3, time: "1 hr ago" },
  { target: "suspicious-shop.test", type: "domain", risk: "High", score: 58, time: "2 hr ago" },
  { target: "192.168.1.1", type: "ip", risk: "Medium", score: 30, time: "3 hr ago" },
];

const riskColor: Record<string, string> = {
  Low: "severity-low",
  Medium: "severity-medium",
  High: "severity-high",
  Critical: "severity-critical",
};

export default function DashboardPage() {
  return (
    <div className="container px-4 py-8 pb-24 space-y-8">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">Security monitoring overview</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map(s => (
          <div key={s.label} className="glass-card-hover p-5 space-y-3">
            <div className="flex items-center justify-between">
              <s.icon className="h-5 w-5 text-primary" />
              <span className="text-xs text-green-400 font-semibold">{s.change}</span>
            </div>
            <div>
              <p className="text-2xl font-bold font-mono">{s.value}</p>
              <p className="text-xs text-muted-foreground">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Threat Distribution */}
      <div className="grid lg:grid-cols-2 gap-4">
        <div className="glass-card p-6 space-y-4">
          <h3 className="font-bold flex items-center gap-2"><Activity className="h-4 w-4 text-primary" /> Threat Distribution</h3>
          <div className="space-y-3">
            {[
              { label: "Malware", pct: 35, color: "bg-red-500" },
              { label: "Phishing", pct: 25, color: "bg-orange-500" },
              { label: "Suspicious Scripts", pct: 20, color: "bg-yellow-500" },
              { label: "Exposed Services", pct: 12, color: "bg-blue-500" },
              { label: "SSL Issues", pct: 8, color: "bg-purple-500" },
            ].map(t => (
              <div key={t.label} className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span>{t.label}</span>
                  <span className="font-mono text-muted-foreground">{t.pct}%</span>
                </div>
                <div className="h-2 rounded-full bg-secondary">
                  <div className={`h-full rounded-full ${t.color} transition-all duration-700`} style={{ width: `${t.pct}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="glass-card p-6 space-y-4">
          <h3 className="font-bold flex items-center gap-2"><TrendingUp className="h-4 w-4 text-primary" /> Risk Level Overview</h3>
          <div className="grid grid-cols-2 gap-3">
            {[
              { level: "Critical", count: 3, color: "from-red-500/20 to-red-500/5 border-red-500/30" },
              { level: "High", count: 5, color: "from-orange-500/20 to-orange-500/5 border-orange-500/30" },
              { level: "Medium", count: 12, color: "from-yellow-500/20 to-yellow-500/5 border-yellow-500/30" },
              { level: "Low", count: 136, color: "from-green-500/20 to-green-500/5 border-green-500/30" },
            ].map(r => (
              <div key={r.level} className={`p-4 rounded-xl bg-gradient-to-b ${r.color} border text-center`}>
                <p className="text-2xl font-bold font-mono">{r.count}</p>
                <p className="text-xs text-muted-foreground">{r.level}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="glass-card p-6 space-y-4">
        <h3 className="font-bold flex items-center gap-2"><Server className="h-4 w-4 text-primary" /> Recent Scans</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-muted-foreground text-xs border-b border-border">
                <th className="text-left py-3 font-medium">Target</th>
                <th className="text-left py-3 font-medium">Type</th>
                <th className="text-left py-3 font-medium">Risk</th>
                <th className="text-left py-3 font-medium">Score</th>
                <th className="text-right py-3 font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map(s => (
                <tr key={s.target} className="border-b border-border/50 hover:bg-secondary/30 transition-colors">
                  <td className="py-3 font-mono">{s.target}</td>
                  <td className="py-3 capitalize text-muted-foreground">{s.type}</td>
                  <td className="py-3"><span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${riskColor[s.risk]}`}>{s.risk}</span></td>
                  <td className="py-3 font-mono">{s.score}</td>
                  <td className="py-3 text-right text-muted-foreground">{s.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
