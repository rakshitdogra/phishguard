import { NextResponse } from "next/server";
export const dynamic = "force-dynamic";
export async function GET() {
  return NextResponse.json({
    ok: true,
    service: "PhishGuard API",
    version: "1.2.0",
    routes: {
      health: "GET /api/health",
      analyzeEmail: "POST /api/analyze",
      analyzeEmailFile: "POST /api/analyze-file (multipart form field: file)",
      checkUrl: "POST /api/check-url (JSON: { url })",
      analyzeAttachment: "POST /api/analyze-attachment (multipart form field: file)",
      attachmentStatus: "GET /api/analyze-attachment/status?id=ANALYSIS_ID"
    },
    providers: {
      virusTotal: Boolean(process.env.VIRUSTOTAL_API_KEY),
      googleSafeBrowsing: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY),
      offlineMode: process.env.PHISHGUARD_OFFLINE_MODE === "true"
    },
    checkedAt: new Date().toISOString()
  }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}
