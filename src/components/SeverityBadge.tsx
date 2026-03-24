import type { AlertSeverity } from "@/lib/scan-engine";

const styles: Record<AlertSeverity, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  info: "severity-info",
};

export default function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${styles[severity]}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}
