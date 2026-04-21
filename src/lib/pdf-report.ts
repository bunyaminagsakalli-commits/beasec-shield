import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

interface VTScanResult {
  target: string;
  targetType: "ip" | "domain" | "url";
  scanDate: string;
  score: number;
  riskLevel: string;
  verdict: string;
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

const NAVY: [number, number, number] = [15, 23, 42];
const BLUE: [number, number, number] = [59, 130, 246];
const MUTED: [number, number, number] = [100, 116, 139];
const RED: [number, number, number] = [239, 68, 68];
const YELLOW: [number, number, number] = [234, 179, 8];
const GREEN: [number, number, number] = [34, 197, 94];

function riskColor(level: string): [number, number, number] {
  if (level === "Critical" || level === "High") return RED;
  if (level === "Medium") return YELLOW;
  return GREEN;
}

export function exportScanReportPdf(result: VTScanResult) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const margin = 40;

  // Header banner
  doc.setFillColor(...NAVY);
  doc.rect(0, 0, pageW, 90, "F");
  doc.setFillColor(...BLUE);
  doc.rect(0, 90, pageW, 3, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.text("BEASEC", margin, 40);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.text("Threat Intelligence Report", margin, 58);
  doc.setFontSize(9);
  doc.setTextColor(180, 200, 230);
  doc.text(`Generated: ${new Date().toLocaleString()}`, margin, 75);

  // Risk badge top-right
  const [r, g, b] = riskColor(result.riskLevel);
  doc.setFillColor(r, g, b);
  doc.roundedRect(pageW - margin - 130, 25, 130, 50, 6, 6, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.text(`${result.score}/100`, pageW - margin - 65, 50, { align: "center" });
  doc.setFontSize(10);
  doc.text(`${result.riskLevel} Risk`, pageW - margin - 65, 67, { align: "center" });

  let y = 120;

  // Target summary
  doc.setTextColor(...NAVY);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.text("Target Information", margin, y);
  y += 8;
  doc.setDrawColor(...BLUE);
  doc.setLineWidth(1);
  doc.line(margin, y, margin + 80, y);
  y += 14;

  autoTable(doc, {
    startY: y,
    theme: "plain",
    styles: { font: "helvetica", fontSize: 10, cellPadding: 4, textColor: NAVY },
    columnStyles: {
      0: { fontStyle: "bold", textColor: MUTED, cellWidth: 110 },
      1: { textColor: NAVY },
    },
    body: [
      ["Target", result.target],
      ["Type", result.targetType.toUpperCase()],
      ["Verdict", result.verdict],
      ["Reputation", String(result.reputation)],
      ["Scan Date", new Date(result.scanDate).toLocaleString()],
      ["Last Analysis", result.lastAnalysisDate ? new Date(result.lastAnalysisDate).toLocaleString() : "—"],
      ["Country", result.country ?? "—"],
      ["AS Owner", result.asOwner ?? "—"],
      ["Network", result.network ?? "—"],
    ],
  });

  y = (doc as any).lastAutoTable.finalY + 24;

  // Detection stats
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.setTextColor(...NAVY);
  doc.text("Detection Statistics", margin, y);
  y += 8;
  doc.line(margin, y, margin + 90, y);
  y += 14;

  const cards: { label: string; value: number; color: [number, number, number] }[] = [
    { label: "Malicious", value: result.stats.malicious, color: RED },
    { label: "Suspicious", value: result.stats.suspicious, color: YELLOW },
    { label: "Harmless", value: result.stats.harmless, color: GREEN },
    { label: "Undetected", value: result.stats.undetected, color: MUTED },
  ];
  const cardW = (pageW - margin * 2 - 30) / 4;
  cards.forEach((c, i) => {
    const x = margin + i * (cardW + 10);
    doc.setFillColor(245, 247, 250);
    doc.roundedRect(x, y, cardW, 60, 4, 4, "F");
    doc.setTextColor(...c.color);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(20);
    doc.text(String(c.value), x + cardW / 2, y + 32, { align: "center" });
    doc.setFontSize(9);
    doc.setTextColor(...MUTED);
    doc.setFont("helvetica", "normal");
    doc.text(c.label.toUpperCase(), x + cardW / 2, y + 50, { align: "center" });
  });
  y += 80;
  doc.setTextColor(...MUTED);
  doc.setFontSize(9);
  doc.text(`Total engines queried: ${result.stats.total}`, margin, y);
  y += 20;

  // Threat categories
  if (result.topThreats.length > 0) {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(14);
    doc.setTextColor(...NAVY);
    doc.text("Threat Categories", margin, y);
    y += 8;
    doc.line(margin, y, margin + 80, y);
    y += 14;
    autoTable(doc, {
      startY: y,
      head: [["Category", "Detections"]],
      body: result.topThreats.map(t => [t.name, String(t.count)]),
      theme: "striped",
      headStyles: { fillColor: NAVY, textColor: 255 },
      styles: { fontSize: 10 },
    });
    y = (doc as any).lastAutoTable.finalY + 20;
  }

  // Site categories
  if (result.categories && Object.keys(result.categories).length > 0) {
    if (y > 700) { doc.addPage(); y = 50; }
    doc.setFont("helvetica", "bold");
    doc.setFontSize(14);
    doc.setTextColor(...NAVY);
    doc.text("Site Categories", margin, y);
    y += 8;
    doc.line(margin, y, margin + 70, y);
    y += 14;
    autoTable(doc, {
      startY: y,
      head: [["Source", "Category"]],
      body: Object.entries(result.categories).map(([s, c]) => [s, c]),
      theme: "striped",
      headStyles: { fillColor: NAVY, textColor: 255 },
      styles: { fontSize: 10 },
    });
    y = (doc as any).lastAutoTable.finalY + 20;
  }

  // Engine findings
  if (y > 680) { doc.addPage(); y = 50; }
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.setTextColor(...NAVY);
  doc.text("Engine Detections", margin, y);
  y += 8;
  doc.line(margin, y, margin + 80, y);
  y += 14;

  if (result.engineFindings.length === 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.setTextColor(...GREEN);
    doc.text("No engine flagged this target as malicious or suspicious.", margin, y);
  } else {
    autoTable(doc, {
      startY: y,
      head: [["Engine", "Category", "Result"]],
      body: result.engineFindings.map(f => [f.engine, f.category, f.result ?? "—"]),
      theme: "striped",
      headStyles: { fillColor: NAVY, textColor: 255 },
      styles: { fontSize: 9, cellPadding: 4 },
      columnStyles: {
        1: { textColor: RED, fontStyle: "bold" },
      },
    });
  }

  // Footer on all pages
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const ph = doc.internal.pageSize.getHeight();
    doc.setDrawColor(220, 225, 235);
    doc.line(margin, ph - 30, pageW - margin, ph - 30);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(...MUTED);
    doc.text("© 2026 BEASEC — Threat Intelligence Platform", margin, ph - 16);
    doc.text(`Page ${i} of ${pageCount}`, pageW - margin, ph - 16, { align: "right" });
  }

  const safe = result.target.replace(/[^a-z0-9.-]/gi, "_").slice(0, 60);
  doc.save(`beasec-report-${safe}-${Date.now()}.pdf`);
}
