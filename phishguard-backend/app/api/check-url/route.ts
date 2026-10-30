import { NextRequest, NextResponse } from "next/server";
import { analyzeEmail } from "@/lib/analyzer";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const MAX_URL_LENGTH = 4096;
function isPrivateOrLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) return true;
  if (host === "::1" || host === "::" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:") || host.startsWith("::ffff:127.")) return true;
  const parts = host.split(".");
  if (parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255)) {
    const [a, b] = parts.map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  return false;
}
export async function POST(request: NextRequest) {
  try {
    const length = Number(request.headers.get("content-length") || 0);
    if (length > 10_000) return NextResponse.json({ error: "URL check request is too large." }, { status: 413 });
    const body = await request.json();
    const raw = typeof body?.url === "string" ? body.url.trim() : "";
    if (!raw || raw.length > MAX_URL_LENGTH) return NextResponse.json({ error: "Provide one HTTP or HTTPS URL up to 4096 characters." }, { status: 400 });
    let url: URL;
    try { url = new URL(raw); } catch { return NextResponse.json({ error: "Invalid URL." }, { status: 400 }); }
    if (url.protocol !== "http:" && url.protocol !== "https:") return NextResponse.json({ error: "Only HTTP and HTTPS URLs can be checked." }, { status: 400 });
    if (!url.hostname || url.username || url.password) return NextResponse.json({ error: "URL must have a hostname and cannot contain embedded credentials." }, { status: 400 });
    if (isPrivateOrLocalHost(url.hostname)) return NextResponse.json({ error: "Local and private-network URLs are not sent to external reputation providers." }, { status: 400 });
    const report = await analyzeEmail({ sender: "scanner@phishguard.invalid", displayName: "PhishGuard URL Scanner", subject: "Website URL check", body: url.href, attachments: "", headers: "", attachmentHashes: [] });
    return NextResponse.json(report, { headers: { "Cache-Control": "no-store, max-age=0", "X-Content-Type-Options": "nosniff" } });
  } catch {
    return NextResponse.json({ error: "Could not check this URL. Verify the request and backend configuration." }, { status: 400, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  }
}
