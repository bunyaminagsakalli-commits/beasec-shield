import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";

const ALLOWED_ORIGINS = [
  "https://beasec.lovable.app",
  "https://id-preview--04e62900-6e78-4a2a-b080-1447188799ea.lovable.app",
];

function buildCorsHeaders(origin: string | null): Record<string, string> {
  const allowOrigin =
    origin && (ALLOWED_ORIGINS.includes(origin) || /\.lovable\.app$/.test(new URL(origin).hostname) || /\.lovableproject\.com$/.test(new URL(origin).hostname))
      ? origin
      : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Vary": "Origin",
    "Access-Control-Allow-Headers":
      "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

type TargetType = "ip" | "domain" | "url";

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
// Simple, conservative domain validator (labels 1-63 chars, total <=253)
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

function isPrivateOrReservedIp(ip: string): boolean {
  const parts = ip.split(".").map((p) => parseInt(p, 10));
  if (parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true; // multicast/reserved
  return false;
}

function detectTargetType(input: string): TargetType {
  const trimmed = input.trim();
  if (IPV4_RE.test(trimmed)) return "ip";
  if (/^https?:\/\//i.test(trimmed) || trimmed.includes("/")) return "url";
  return "domain";
}

function validateAndNormalize(input: string): { ok: true; type: TargetType; value: string } | { ok: false; reason: string } {
  if (typeof input !== "string") return { ok: false, reason: "Target must be a string" };
  const trimmed = input.trim();
  if (trimmed.length === 0 || trimmed.length > 2048) return { ok: false, reason: "Invalid target length" };
  if (/[\s<>"'`\\]/.test(trimmed)) return { ok: false, reason: "Invalid characters in target" };

  const type = detectTargetType(trimmed);

  if (type === "ip") {
    if (!IPV4_RE.test(trimmed)) return { ok: false, reason: "Invalid IPv4 address" };
    if (isPrivateOrReservedIp(trimmed)) return { ok: false, reason: "Private or reserved IP not allowed" };
    return { ok: true, type, value: trimmed };
  }

  if (type === "domain") {
    const host = trimmed.toLowerCase();
    if (!DOMAIN_RE.test(host)) return { ok: false, reason: "Invalid domain name" };
    return { ok: true, type, value: host };
  }

  // URL
  let urlStr = trimmed;
  if (!/^https?:\/\//i.test(urlStr)) urlStr = "https://" + urlStr;
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return { ok: false, reason: "Invalid URL" };
  }
  if (!/^https?:$/.test(parsed.protocol)) return { ok: false, reason: "Only http/https URLs allowed" };
  const host = parsed.hostname;
  if (IPV4_RE.test(host)) {
    if (isPrivateOrReservedIp(host)) return { ok: false, reason: "Private or reserved host not allowed" };
  } else if (!DOMAIN_RE.test(host)) {
    return { ok: false, reason: "Invalid host in URL" };
  }
  if (urlStr.length > 2048) return { ok: false, reason: "URL too long" };
  return { ok: true, type: "url", value: urlStr };
}

function urlToVtId(url: string): string {
  const bytes = new TextEncoder().encode(url);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function vtFetch(path: string, apiKey: string, init?: RequestInit) {
  const res = await fetch(`https://www.virustotal.com/api/v3${path}`, {
    ...init,
    headers: {
      "x-apikey": apiKey,
      "Accept": "application/json",
      ...(init?.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

Deno.serve(async (req) => {
  const corsHeaders = buildCorsHeaders(req.headers.get("origin"));
  const jsonHeaders = { ...corsHeaders, "Content-Type": "application/json" };

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: jsonHeaders });
  }

  // --- AuthN: require valid Supabase JWT ---
  const authHeader = req.headers.get("Authorization") || req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  if (!supabaseUrl || !anonKey) {
    console.error("virustotal-scan: missing SUPABASE_URL/SUPABASE_ANON_KEY");
    return new Response(JSON.stringify({ error: "Service misconfigured" }), { status: 500, headers: jsonHeaders });
  }

  const supabase = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authHeader } },
  });
  const token = authHeader.replace(/^Bearer\s+/i, "");
  const { data: claimsData, error: claimsError } = await supabase.auth.getClaims(token);
  if (claimsError || !claimsData?.claims?.sub) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
  }

  const apiKey = Deno.env.get("VIRUSTOTAL_API_KEY");
  if (!apiKey) {
    console.error("virustotal-scan: VIRUSTOTAL_API_KEY not configured");
    return new Response(JSON.stringify({ error: "Service misconfigured" }), { status: 500, headers: jsonHeaders });
  }

  // --- Parse + validate body ---
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), { status: 400, headers: jsonHeaders });
  }
  const rawTarget = (body as { target?: unknown })?.target;
  if (typeof rawTarget !== "string") {
    return new Response(JSON.stringify({ error: "Field 'target' is required" }), { status: 400, headers: jsonHeaders });
  }
  const validated = validateAndNormalize(rawTarget);
  if (!validated.ok) {
    return new Response(JSON.stringify({ error: validated.reason }), { status: 400, headers: jsonHeaders });
  }
  const { type: targetType, value: normalized } = validated;

  try {
    let endpoint = "";
    if (targetType === "ip") endpoint = `/ip_addresses/${encodeURIComponent(normalized)}`;
    else if (targetType === "domain") endpoint = `/domains/${encodeURIComponent(normalized)}`;
    else endpoint = `/urls/${urlToVtId(normalized)}`;

    let result = await vtFetch(endpoint, apiKey);

    if (targetType === "url" && result.status === 404) {
      const submit = await vtFetch(`/urls`, apiKey, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `url=${encodeURIComponent(normalized)}`,
      });
      if (!submit.ok) {
        console.error("virustotal-scan: submit failed", { status: submit.status, data: submit.data });
        return new Response(JSON.stringify({ error: "Scan submission failed. Please try again." }), { status: 502, headers: jsonHeaders });
      }
      await new Promise((r) => setTimeout(r, 2500));
      result = await vtFetch(endpoint, apiKey);
    }

    if (!result.ok) {
      console.error("virustotal-scan: lookup failed", { status: result.status, data: result.data });
      if (result.status === 401 || result.status === 403) {
        return new Response(JSON.stringify({ error: "Threat intelligence service authentication failed." }), { status: 502, headers: jsonHeaders });
      }
      if (result.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limit reached. Please try again shortly." }), { status: 429, headers: jsonHeaders });
      }
      if (result.status === 404) {
        return new Response(JSON.stringify({ error: "Target not found in threat intelligence database." }), { status: 404, headers: jsonHeaders });
      }
      return new Response(JSON.stringify({ error: "Threat intelligence lookup failed. Please try again." }), { status: 502, headers: jsonHeaders });
    }

    const attrs = result.data?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const analysisResults = attrs.last_analysis_results || {};
    const reputation = attrs.reputation ?? 0;

    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const harmless = stats.harmless ?? 0;
    const undetected = stats.undetected ?? 0;
    const total = malicious + suspicious + harmless + undetected;

    let score = 0;
    if (total > 0) {
      score = Math.min(100, Math.round(((malicious * 8 + suspicious * 4) / total) * 100));
    }
    if (reputation < -20) score = Math.min(100, score + 10);

    let riskLevel: "Low" | "Medium" | "High" | "Critical" = "Low";
    if (score >= 75) riskLevel = "Critical";
    else if (score >= 50) riskLevel = "High";
    else if (score >= 25) riskLevel = "Medium";

    let verdict: "Clean" | "Suspicious" | "Malicious" | "High Risk" = "Clean";
    if (malicious >= 5) verdict = "Malicious";
    else if (malicious >= 1) verdict = "High Risk";
    else if (suspicious >= 1) verdict = "Suspicious";

    const categoryCounts: Record<string, number> = {};
    Object.values(analysisResults).forEach((r: any) => {
      const cat = r?.result || r?.category;
      if (cat && typeof cat === "string" && cat !== "clean" && cat !== "unrated") {
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      }
    });
    const topThreats = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, count]) => ({ name, count }));

    const engineFindings = Object.entries(analysisResults)
      .filter(([_, r]: any) => r?.category === "malicious" || r?.category === "suspicious")
      .map(([engine, r]: any) => ({
        engine,
        category: r.category,
        result: r.result || null,
      }));

    return new Response(
      JSON.stringify({
        target: normalized,
        targetType,
        scanDate: new Date().toISOString(),
        score,
        riskLevel,
        verdict,
        stats: { malicious, suspicious, harmless, undetected, total },
        reputation,
        topThreats,
        engineFindings,
        lastAnalysisDate: attrs.last_analysis_date
          ? new Date(attrs.last_analysis_date * 1000).toISOString()
          : null,
        whois: attrs.whois || null,
        categories: attrs.categories || null,
        country: attrs.country || null,
        asOwner: attrs.as_owner || null,
        network: attrs.network || null,
      }),
      { status: 200, headers: jsonHeaders }
    );
  } catch (err) {
    console.error("virustotal-scan: unhandled error", err);
    return new Response(JSON.stringify({ error: "An unexpected error occurred. Please try again." }), {
      status: 500,
      headers: jsonHeaders,
    });
  }
});
