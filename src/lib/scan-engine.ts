// BEASEC Scan Engine - Simulated Threat Intelligence

export type TargetType = 'ip' | 'domain' | 'url';
export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';
export type Verdict = 'Clean' | 'Suspicious' | 'Malicious' | 'High Risk';
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'info';

export interface Alert {
  id: string;
  severity: AlertSeverity;
  title: string;
  description: string;
  timestamp: string;
}

export interface Recommendation {
  id: string;
  priority: AlertSeverity;
  title: string;
  description: string;
  action: string;
}

export interface SourceResult {
  source: string;
  status: 'clean' | 'suspicious' | 'malicious' | 'error' | 'not_queried';
  details: string;
  confidence: number;
}

export interface ScanResult {
  target: string;
  targetType: TargetType;
  scanDate: string;
  overallScore: number;
  riskLevel: RiskLevel;
  verdict: Verdict;
  threatType?: string;
  sslStatus: { valid: boolean; issuer: string; expiry: string; grade: string };
  malwareStatus: { detected: boolean; details: string };
  blacklistStatus: { listed: boolean; sources: string[] };
  securityHeaders: { score: number; missing: string[]; present: string[] };
  uptime: { percentage: number; lastCheck: string };
  softwareStatus: { outdated: boolean; details: string };
  alerts: Alert[];
  recommendations: Recommendation[];
  sourceResults: SourceResult[];
}

export function detectTargetType(input: string): TargetType {
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) return 'url';
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return 'ip';
  return 'domain';
}

export function normalizeTarget(input: string): string {
  let t = input.trim().toLowerCase();
  if (detectTargetType(input) === 'domain') {
    t = t.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/.*$/, '');
  }
  return t;
}

function getRiskLevel(score: number): RiskLevel {
  if (score >= 75) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}

function getVerdict(score: number): Verdict {
  if (score >= 75) return 'Malicious';
  if (score >= 50) return 'High Risk';
  if (score >= 25) return 'Suspicious';
  return 'Clean';
}

// Demo profiles for known targets
const demoProfiles: Record<string, Partial<ScanResult>> = {
  'google.com': {
    overallScore: 5,
    sslStatus: { valid: true, issuer: 'Google Trust Services', expiry: '2027-01-15', grade: 'A+' },
    malwareStatus: { detected: false, details: 'No malware detected' },
    blacklistStatus: { listed: false, sources: [] },
    securityHeaders: { score: 95, missing: [], present: ['HSTS', 'X-Frame-Options', 'CSP', 'X-Content-Type-Options'] },
    uptime: { percentage: 99.99, lastCheck: new Date().toISOString() },
    softwareStatus: { outdated: false, details: 'All components up to date' },
  },
  'example-malware.test': {
    overallScore: 92,
    threatType: 'Trojan / Malware Delivery',
    sslStatus: { valid: false, issuer: 'Unknown CA', expiry: '2024-03-01', grade: 'F' },
    malwareStatus: { detected: true, details: 'Trojan.GenericKD detected in hosted scripts' },
    blacklistStatus: { listed: true, sources: ['VirusTotal', 'URLhaus', 'Google Safe Browsing'] },
    securityHeaders: { score: 10, missing: ['HSTS', 'CSP', 'X-Frame-Options', 'X-Content-Type-Options'], present: [] },
    uptime: { percentage: 45.2, lastCheck: new Date().toISOString() },
    softwareStatus: { outdated: true, details: 'Apache 2.2.15 (severely outdated, known CVEs)' },
  },
  'suspicious-shop.test': {
    overallScore: 58,
    threatType: 'Possible Phishing Infrastructure',
    sslStatus: { valid: true, issuer: "Let's Encrypt", expiry: '2026-06-01', grade: 'B' },
    malwareStatus: { detected: false, details: 'No confirmed malware, suspicious scripts detected' },
    blacklistStatus: { listed: true, sources: ['PhishTank'] },
    securityHeaders: { score: 35, missing: ['CSP', 'X-Frame-Options'], present: ['HSTS', 'X-Content-Type-Options'] },
    uptime: { percentage: 88.5, lastCheck: new Date().toISOString() },
    softwareStatus: { outdated: true, details: 'WordPress 5.2 (outdated, multiple known vulnerabilities)' },
  },
  '192.168.1.1': {
    overallScore: 30,
    sslStatus: { valid: false, issuer: 'Self-signed', expiry: '2025-12-01', grade: 'C' },
    malwareStatus: { detected: false, details: 'No malware detected' },
    blacklistStatus: { listed: false, sources: [] },
    securityHeaders: { score: 20, missing: ['HSTS', 'CSP', 'X-Frame-Options', 'X-Content-Type-Options'], present: [] },
    uptime: { percentage: 99.1, lastCheck: new Date().toISOString() },
    softwareStatus: { outdated: true, details: 'Router firmware version 1.2.3 (update available)' },
  },
  '8.8.8.8': {
    overallScore: 3,
    sslStatus: { valid: true, issuer: 'Google Trust Services', expiry: '2027-06-01', grade: 'A+' },
    malwareStatus: { detected: false, details: 'No malware detected' },
    blacklistStatus: { listed: false, sources: [] },
    securityHeaders: { score: 90, missing: [], present: ['HSTS', 'X-Content-Type-Options'] },
    uptime: { percentage: 99.999, lastCheck: new Date().toISOString() },
    softwareStatus: { outdated: false, details: 'Google Public DNS - maintained' },
  },
};

function generateSourceResults(target: string, targetType: TargetType, score: number): SourceResult[] {
  const isMalicious = score >= 50;
  const isSuspicious = score >= 25;

  const ipSources = ['VirusTotal', 'AbuseIPDB', 'Shodan', 'GreyNoise', 'Censys', 'AlienVault OTX'];
  const domainSources = ['VirusTotal', 'SecurityTrails', 'AlienVault OTX', 'urlscan.io', 'URLhaus'];
  const urlSources = ['VirusTotal', 'urlscan.io', 'URLhaus', 'AlienVault OTX'];

  const sources = targetType === 'ip' ? ipSources : targetType === 'domain' ? domainSources : urlSources;

  return sources.map(source => {
    if (isMalicious) {
      const rand = Math.random();
      return {
        source,
        status: rand > 0.3 ? 'malicious' as const : 'suspicious' as const,
        details: rand > 0.3 ? `Flagged as malicious by ${source}` : `Suspicious activity reported`,
        confidence: 70 + Math.floor(Math.random() * 30),
      };
    }
    if (isSuspicious) {
      const rand = Math.random();
      return {
        source,
        status: rand > 0.6 ? 'suspicious' as const : 'clean' as const,
        details: rand > 0.6 ? `Low-confidence suspicious indicator` : `No threats found`,
        confidence: 40 + Math.floor(Math.random() * 40),
      };
    }
    return {
      source,
      status: 'clean' as const,
      details: `No threats detected by ${source}`,
      confidence: 90 + Math.floor(Math.random() * 10),
    };
  });
}

function generateAlerts(result: Partial<ScanResult>): Alert[] {
  const alerts: Alert[] = [];
  const now = new Date().toISOString();

  if (result.sslStatus && !result.sslStatus.valid) {
    alerts.push({ id: 'a1', severity: 'critical', title: 'SSL Certificate Issue', description: `SSL certificate is invalid or expired (Grade: ${result.sslStatus.grade})`, timestamp: now });
  }
  if (result.malwareStatus?.detected) {
    alerts.push({ id: 'a2', severity: 'critical', title: 'Malware Detected', description: result.malwareStatus.details, timestamp: now });
  }
  if (result.blacklistStatus?.listed) {
    alerts.push({ id: 'a3', severity: 'critical', title: 'Blacklist Detection', description: `Target found on ${result.blacklistStatus.sources?.length} blacklist(s): ${result.blacklistStatus.sources?.join(', ')}`, timestamp: now });
  }
  if (result.securityHeaders && result.securityHeaders.score < 50) {
    alerts.push({ id: 'a4', severity: 'medium', title: 'Weak Security Headers', description: `Missing: ${result.securityHeaders.missing?.join(', ')}`, timestamp: now });
  }
  if (result.softwareStatus?.outdated) {
    alerts.push({ id: 'a5', severity: 'medium', title: 'Outdated Software', description: result.softwareStatus.details, timestamp: now });
  }
  if (alerts.length === 0) {
    alerts.push({ id: 'a6', severity: 'info', title: 'All Clear', description: 'No significant security issues detected. Monitoring active.', timestamp: now });
  }
  return alerts;
}

function generateRecommendations(result: Partial<ScanResult>): Recommendation[] {
  const recs: Recommendation[] = [];

  if (result.sslStatus && !result.sslStatus.valid) {
    recs.push({ id: 'r1', priority: 'critical', title: 'Renew SSL Certificate', description: 'Your SSL certificate is invalid or expired, leaving connections vulnerable to interception.', action: 'Obtain and install a valid SSL certificate from a trusted Certificate Authority.' });
  }
  if (result.softwareStatus?.outdated) {
    recs.push({ id: 'r2', priority: 'high', title: 'Update Software Components', description: 'Outdated software exposes your system to known vulnerabilities.', action: 'Update all software components to their latest stable versions.' });
  }
  if (result.malwareStatus?.detected) {
    recs.push({ id: 'r3', priority: 'critical', title: 'Remove Malware', description: 'Active malware has been detected on this target.', action: 'Isolate the system, perform a full malware scan, and remove all malicious files.' });
  }
  if (result.blacklistStatus?.listed) {
    recs.push({ id: 'r4', priority: 'high', title: 'Request Blacklist Removal', description: 'Being blacklisted impacts reputation and deliverability.', action: 'Address the root cause and submit removal requests to each blacklist provider.' });
  }
  if (result.securityHeaders && result.securityHeaders.score < 50) {
    recs.push({ id: 'r5', priority: 'medium', title: 'Implement Security Headers', description: 'Missing security headers leave your application vulnerable to common attacks.', action: `Add the following headers: ${result.securityHeaders.missing?.join(', ')}` });
  }
  if (recs.length === 0) {
    recs.push({ id: 'r6', priority: 'info', title: 'Continue Monitoring', description: 'No immediate actions required. Maintain regular security monitoring.', action: 'Schedule periodic scans to ensure continued security.' });
  }
  return recs;
}

// Fallback profile for unknown targets
function generateFallbackProfile(target: string, targetType: TargetType): Partial<ScanResult> {
  const score = 8 + Math.floor(Math.random() * 25);
  return {
    overallScore: score,
    sslStatus: { valid: true, issuer: "Let's Encrypt", expiry: '2027-03-01', grade: 'A' },
    malwareStatus: { detected: false, details: 'No malware detected' },
    blacklistStatus: { listed: false, sources: [] },
    securityHeaders: { score: 55 + Math.floor(Math.random() * 30), missing: ['CSP'], present: ['HSTS', 'X-Content-Type-Options', 'X-Frame-Options'] },
    uptime: { percentage: 95 + Math.random() * 4.9, lastCheck: new Date().toISOString() },
    softwareStatus: { outdated: false, details: 'No outdated components detected' },
  };
}

export function performScan(input: string): ScanResult {
  const target = normalizeTarget(input);
  const targetType = detectTargetType(input);
  const profile = demoProfiles[target] || generateFallbackProfile(target, targetType);
  const score = profile.overallScore || 10;

  const result: ScanResult = {
    target,
    targetType,
    scanDate: new Date().toISOString(),
    overallScore: score,
    riskLevel: getRiskLevel(score),
    verdict: getVerdict(score),
    threatType: profile.threatType,
    sslStatus: profile.sslStatus!,
    malwareStatus: profile.malwareStatus!,
    blacklistStatus: profile.blacklistStatus!,
    securityHeaders: profile.securityHeaders!,
    uptime: profile.uptime!,
    softwareStatus: profile.softwareStatus!,
    alerts: [],
    recommendations: [],
    sourceResults: generateSourceResults(target, targetType, score),
  };

  result.alerts = generateAlerts(result);
  result.recommendations = generateRecommendations(result);

  return result;
}

export const demoTargets = [
  { label: 'Google (Clean)', value: 'google.com' },
  { label: 'Malware Site (Critical)', value: 'example-malware.test' },
  { label: 'Phishing Shop (High)', value: 'suspicious-shop.test' },
  { label: 'Local Router (Medium)', value: '192.168.1.1' },
  { label: 'Google DNS (Clean)', value: '8.8.8.8' },
];
