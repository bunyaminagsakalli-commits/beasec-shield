import { Shield, Github, Globe, BookOpen, Users, Code2, Database, Cpu } from "lucide-react";

const techStack = [
  { icon: Code2, label: "React + TypeScript", desc: "Modern component-based frontend" },
  { icon: Globe, label: "Responsive Design", desc: "Web + mobile-optimized interface" },
  { icon: Database, label: "Threat Intelligence", desc: "Multi-source data aggregation" },
  { icon: Cpu, label: "Risk Engine", desc: "Normalized scoring & classification" },
  { icon: Shield, label: "Security Analysis", desc: "SSL, headers, malware, blacklists" },
  { icon: BookOpen, label: "OWASP / MITRE", desc: "Future vulnerability mapping" },
];

export default function AboutPage() {
  return (
    <div className="container px-4 py-8 pb-24 space-y-10">
      <div className="max-w-2xl mx-auto text-center space-y-4">
        <div className="inline-flex items-center gap-2 p-3 rounded-xl bg-primary/10">
          <Shield className="h-8 w-8 text-primary" />
        </div>
        <h1 className="text-3xl font-bold">About BEASEC</h1>
        <p className="text-muted-foreground">
          BEASEC is a dual-platform cybersecurity monitoring system designed as an academic prototype 
          for real-time threat intelligence, vulnerability detection, and security assessment.
        </p>
      </div>

      {/* Project Info */}
      <div className="grid md:grid-cols-2 gap-4 max-w-3xl mx-auto">
        <div className="glass-card p-6 space-y-4">
          <h3 className="font-bold">Project Information</h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between"><span className="text-muted-foreground">Project Name</span><span className="font-semibold">BEASEC</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Developer</span><span className="font-semibold">Ekrem Ağsakallı</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">University</span><span className="font-semibold">Riga Nordic University</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Type</span><span className="font-semibold">Academic Prototype</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Year</span><span className="font-semibold">2026</span></div>
          </div>
        </div>

        <div className="glass-card p-6 space-y-4">
          <h3 className="font-bold">Platform Scope</h3>
          <ul className="space-y-2 text-sm text-muted-foreground">
            <li className="flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-primary" /> Multi-source threat intelligence aggregation</li>
            <li className="flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-primary" /> IP, domain, and URL security scanning</li>
            <li className="flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-primary" /> Risk scoring with evidence classification</li>
            <li className="flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-primary" /> Alert and recommendation engine</li>
            <li className="flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-primary" /> OWASP / MITRE / CVE mapping (planned)</li>
            <li className="flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-primary" /> Responsive web + mobile interface</li>
          </ul>
        </div>
      </div>

      {/* Tech Stack */}
      <div className="max-w-3xl mx-auto">
        <h2 className="text-xl font-bold mb-4 text-center">Technology & Architecture</h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {techStack.map(t => (
            <div key={t.label} className="glass-card-hover p-4 flex items-start gap-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <t.icon className="h-4 w-4 text-primary" />
              </div>
              <div>
                <p className="font-semibold text-sm">{t.label}</p>
                <p className="text-xs text-muted-foreground">{t.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Intelligence sources */}
      <div className="max-w-3xl mx-auto glass-card p-6 space-y-4">
        <h3 className="font-bold">Threat Intelligence Sources (Architecture)</h3>
        <p className="text-sm text-muted-foreground">The backend aggregation layer is designed to normalize responses from:</p>
        <div className="flex flex-wrap gap-2">
          {['VirusTotal', 'AbuseIPDB', 'AlienVault OTX', 'urlscan.io', 'URLhaus', 'SecurityTrails', 'Shodan', 'GreyNoise', 'Censys'].map(s => (
            <span key={s} className="px-3 py-1.5 rounded-lg bg-secondary text-xs font-mono">{s}</span>
          ))}
        </div>
      </div>

      {/* Future */}
      <div className="max-w-3xl mx-auto glass-card p-6 border border-primary/20 space-y-3">
        <h3 className="font-bold text-primary">Future Vulnerability Intelligence Module</h3>
        <p className="text-sm text-muted-foreground">
          Planned integration with OWASP Top 10, OWASP ASVS, OWASP WSTG, MITRE CWE, CVE/NVD, CISA KEV, 
          and MITRE ATT&CK for comprehensive vulnerability intelligence mapping including finding name, severity, 
          confidence, CWE classification, CVE exposure, KEV relevance, and ATT&CK technique mapping.
        </p>
      </div>
    </div>
  );
}
