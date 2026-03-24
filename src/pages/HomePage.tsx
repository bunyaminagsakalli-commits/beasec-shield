import { Link } from "react-router-dom";
import { Shield, Search, BarChart3, Bell, Globe, Lock, Cpu, ArrowRight } from "lucide-react";

const features = [
  { icon: Search, title: "Universal Scanner", desc: "Scan IPs, domains, and URLs with multi-source threat intelligence." },
  { icon: BarChart3, title: "Risk Scoring", desc: "Normalized 0-100 risk scoring with evidence-based classification." },
  { icon: Bell, title: "Smart Alerts", desc: "Severity-prioritized alerts from critical to informational." },
  { icon: Globe, title: "Source Aggregation", desc: "Intelligence from VirusTotal, AbuseIPDB, Shodan, and more." },
  { icon: Lock, title: "SSL & Headers", desc: "Certificate validation and security header analysis." },
  { icon: Cpu, title: "Threat Classification", desc: "Malware, phishing, botnet, and exploit detection." },
];

export default function HomePage() {
  return (
    <div className="pb-24">
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent" />
        <div className="container px-4 pt-20 pb-16 relative">
          <div className="max-w-3xl mx-auto text-center space-y-6 animate-fade-in-up">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold">
              <Shield className="h-3.5 w-3.5" />
              Cybersecurity Monitoring Platform
            </div>
            <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight leading-tight">
              Protect Your Digital
              <span className="text-gradient block">Infrastructure</span>
            </h1>
            <p className="text-lg text-muted-foreground max-w-xl mx-auto">
              Real-time threat intelligence, vulnerability detection, and security monitoring for IPs, domains, and URLs.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
              <Link
                to="/scan"
                className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl bg-primary text-primary-foreground font-semibold hover:bg-primary/90 transition-colors"
              >
                <Search className="h-4 w-4" />
                Start Scanning
              </Link>
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl bg-secondary text-secondary-foreground font-semibold hover:bg-secondary/80 transition-colors"
              >
                View Dashboard
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="container px-4 py-16">
        <h2 className="text-2xl font-bold text-center mb-10">Platform Capabilities</h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map(f => (
            <div key={f.title} className="glass-card-hover p-6 space-y-3">
              <div className="p-2.5 rounded-lg bg-primary/10 w-fit">
                <f.icon className="h-5 w-5 text-primary" />
              </div>
              <h3 className="font-semibold">{f.title}</h3>
              <p className="text-sm text-muted-foreground">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="container px-4 py-12">
        <div className="glass-card p-8 md:p-12 text-center cyber-glow space-y-4">
          <h2 className="text-2xl font-bold">Ready to Secure Your Assets?</h2>
          <p className="text-muted-foreground max-w-md mx-auto">Enter any IP, domain, or URL to receive a comprehensive threat intelligence report.</p>
          <Link to="/scan" className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl bg-primary text-primary-foreground font-semibold hover:bg-primary/90 transition-colors">
            Launch Scanner
            <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </div>
  );
}
