import { corsHeaders } from "@supabase/supabase-js/cors";

interface ScanRequest {
  target: string;
}

type TargetType = "ip" | "domain" | "url";

function detectTargetType(input: string): TargetType {
  const trimmed = input.trim();
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return "ip";
  // URL with scheme or path
  if (/^https?:\/\//i.test(trimmed) || trimmed.includes("/")) return "url";
  // domain
  return "domain";
}

function normalizeTarget(input: string, type: TargetType): string {
  let t = input.trim();
  if (type === "url" && !/^https?:\/\//i.test(t)) {
    t = "https://" + t;
  }
  if (type === "domain") {
    t = t.replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  }
  return t;
}

// VT requires URL identifier as base64url(no padding) of the URL
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
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const apiKey = Deno.env.get("VIRUSTOTAL_API_KEY");
    if (!apiKey) {
      return new Response(JSON.stringify({ error: "VIRUSTOTAL_API_KEY not configured" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = (await req.json().catch(() => ({}))) as Partial<ScanRequest>;
    const target = (body.target || "").toString().trim();
    if (!target || target.length > 2048) {
      return new Response(JSON.stringify({ error: "Invalid target" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const targetType = detectTargetType(target);
    const normalized = normalizeTarget(target, targetType);

    let endpoint = "";
    if (targetType === "ip") endpoint = `/ip_addresses/${encodeURIComponent(normalized)}`;
    else if (targetType === "domain") endpoint = `/domains/${encodeURIComponent(normalized)}`;
    else endpoint = `/urls/${urlToVtId(normalized)}`;

    let result = await vtFetch(endpoint, apiKey);

    // For URLs not yet analyzed, submit then poll once
    if (targetType === "url" && result.status === 404) {
      const submit = await vtFetch(`/urls`, apiKey, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `url=${encodeURIComponent(normalized)}`,
      });
      if (!submit.ok) {
        return new Response(JSON.stringify({ error: "VirusTotal submit failed", details: submit.data }), {
          status: 502,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      // brief wait then re-fetch
      await new Promise((r) => setTimeout(r, 2500));
      result = await vtFetch(endpoint, apiKey);
    }

    if (!result.ok) {
      return new Response(JSON.stringify({ error: "VirusTotal request failed", status: result.status, details: result.data }), {
        status: result.status === 401 ? 401 : 502,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
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

    // Risk score 0-100
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

    // Categorize threat type from analysis result categories
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

    // Engine-by-engine listing (only those that flagged something)
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
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    console.error("virustotal-scan error", err);
    const msg = err instanceof Error ? err.message : "Unknown error";
    return new Response(JSON.stringify({ error: msg }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});