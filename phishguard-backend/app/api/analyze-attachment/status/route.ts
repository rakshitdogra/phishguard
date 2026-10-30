import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const id = request.nextUrl.searchParams.get("id") || "";
  if (!id || id.length > 300 || !/^[A-Za-z0-9_-]+$/.test(id)) {
    return NextResponse.json({ error: "Invalid analysis ID." }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return NextResponse.json({ error: "VirusTotal is not configured." }, { status: 503, headers: { "Cache-Control": "no-store" } });
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(id)}`, {
      headers: { "x-apikey": apiKey }, cache: "no-store", signal: AbortSignal.timeout(10000)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) return NextResponse.json({ error: "Could not retrieve scan status." }, { status: 502, headers: { "Cache-Control": "no-store" } });
    const attributes = data?.data?.attributes || {};
    const state = String(attributes.status || "queued").toLowerCase();
    const stats = attributes.stats || {};
    if (state !== "completed") {
      return NextResponse.json({ status: state === "in-progress" ? "in progress" : "queued", completed: false }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
    }
    const malicious = Number(stats.malicious || 0), suspicious = Number(stats.suspicious || 0);
    return NextResponse.json({
      status: malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "no known threat detected",
      completed: true,
      stats: { malicious, suspicious, harmless: Number(stats.harmless || 0), undetected: Number(stats.undetected || 0) }
    }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  } catch {
    return NextResponse.json({ error: "Could not retrieve scan status." }, { status: 502, headers: { "Cache-Control": "no-store" } });
  }
}
