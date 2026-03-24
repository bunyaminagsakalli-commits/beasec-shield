import type { RiskLevel } from "@/lib/scan-engine";

const colors: Record<RiskLevel, string> = {
  Low: "text-green-400",
  Medium: "text-yellow-400",
  High: "text-orange-400",
  Critical: "text-red-400",
};

const bgColors: Record<RiskLevel, string> = {
  Low: "from-green-500/20 to-green-500/5",
  Medium: "from-yellow-500/20 to-yellow-500/5",
  High: "from-orange-500/20 to-orange-500/5",
  Critical: "from-red-500/20 to-red-500/5",
};

export default function RiskGauge({ score, level }: { score: number; level: RiskLevel }) {
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className={`glass-card p-6 flex flex-col items-center gap-4 bg-gradient-to-b ${bgColors[level]}`}>
      <svg width="140" height="140" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="54" fill="none" stroke="hsl(var(--border))" strokeWidth="8" />
        <circle
          cx="60" cy="60" r="54" fill="none"
          stroke="currentColor"
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={`${colors[level]} transition-all duration-1000`}
          transform="rotate(-90 60 60)"
        />
        <text x="60" y="55" textAnchor="middle" className="fill-foreground text-2xl font-bold font-mono" fontSize="28">{score}</text>
        <text x="60" y="75" textAnchor="middle" className="fill-muted-foreground text-xs" fontSize="11">/100</text>
      </svg>
      <div className="text-center">
        <span className={`text-sm font-semibold ${colors[level]}`}>{level} Risk</span>
      </div>
    </div>
  );
}
